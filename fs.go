// +build ignore

package main

/*
import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/pprof"
	"sync"
	"time"

	"log"

	"github.com/vtolstov/svirtnet/internal/github.com/alexzorin/libvirt-go"
	"github.com/vtolstov/svirtnet/internal/golang.org/x/net/context"

	"github.com/vtolstov/svirtnet/internal/bazil.org/fuse"
	"github.com/vtolstov/svirtnet/internal/bazil.org/fuse/fs"
)

type ISO struct {
	Disks []ISODisk `xml:"disk"`
}

type ISODisk struct {
	Type   string `xml:"type,attr"`
	Device string `xml:"device,attr"`
	Driver struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"driver"`
	Source struct {
		URL string `xml:"url,attr"`
	} `xml:"source"`
	Target struct {
		Name string `xml:"name,attr"`
	} `xml:"target"`
}

type Metadata struct {
	ISO ISO `xml:"iso,omitempty"`
}

var httpTransport *http.Transport = &http.Transport{
	Dial:               (&net.Dialer{DualStack: true}).Dial,
	TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	DisableCompression: true,
	DisableKeepAlives:  true,
}
var httpClient *http.Client = &http.Client{Transport: httpTransport, Timeout: 100000 * time.Second}

func printf(msg interface{}) {
	log.Printf("%s\n", msg)
}

type ReadSeekCloser interface {
	io.Reader
	io.Closer
	io.Seeker
}

type httpReadSeekCloser struct {
	u string

	r io.ReadCloser

	offset int64
	size   int64

	pos int64

	sync.Mutex
}

func httpReadSeekCloserNew(u string) (*httpReadSeekCloser, error) {
	req, err := http.NewRequest("HEAD", u, nil)
	if err != nil {
		panic(err)
		return nil, err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		panic(err)
		return nil, err
	}

	if res.ContentLength < 1 {
		panic("rrrr")
		return nil, fmt.Errorf("unknown ContentLength")
	}

	req, err = http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	res, err = httpClient.Do(req)
	if err != nil {
		defer res.Body.Close()
		return nil, err
	}

	h := &httpReadSeekCloser{u: u, size: res.ContentLength, r: res.Body}

	return h, nil
}

func (h *httpReadSeekCloser) Read(b []byte) (int, error) {
	//	h.Lock()
	//	defer h.Unlock()

	if h.pos == h.offset {
		n, err := io.ReadFull(h.r, b)
		if err != nil && err != io.EOF {
			return n, err
		}
		h.pos += int64(n)
		h.offset = h.pos
		if h.pos == h.size {
			return n, nil
		}
		return n, err
	} else {
		h.r.Close()
		req, err := http.NewRequest("GET", h.u, nil)
		if err != nil {
			return 0, fuse.EIO
		}

		//		req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d", h.offset, h.offset+int64(len(b)-1)))
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-", h.offset))
		res, err := httpClient.Do(req)
		if err != nil {
			return 0, fuse.EIO
		}
		n, err := io.ReadFull(res.Body, b)
		if err != nil && err != io.EOF {
			res.Body.Close()
			return n, err
		}
		h.pos += int64(n)
		h.offset = h.pos
		h.r = res.Body
		if h.pos == h.size {
			return n, nil
		}
		return n, err
	}

	return 0, fmt.Errorf("unexpected read error")
}

func (h *httpReadSeekCloser) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case os.SEEK_CUR:
		h.offset += offset
	case os.SEEK_SET:
		h.offset = offset
	case os.SEEK_END:
		h.size += offset
	default:
		return 0, fmt.Errorf("unknown whence: %d", whence)
	}
	return h.offset, nil
}

func (h *httpReadSeekCloser) Close() error {
	if h.r == nil {
		return nil
	}
	return h.r.Close()
}

func main() {
	var err error

	cpuprof, err := os.Create("test.prof")
	if err != nil {
		log.Printf("failed to create prof %s", err.Error())
	}
	pprof.StartCPUProfile(cpuprof)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)

	go func() {
		<-c
		defer pprof.StopCPUProfile()

	}()

	//	fuse.Debug = printf

	fuse.Unmount("/srv/iso")

	_, err = os.Stat("/srv/iso")
	if err != nil {
		err = os.MkdirAll("/srv/iso", 0770)
		if err != nil {
			log.Printf("Failed to create dir: %s\n", err.Error())
			os.Exit(1)
		}
	}

	virconn, err := libvirt.NewVirConnectionReadOnly("qemu:///system")
	if err == nil {
		defer virconn.UnrefAndCloseConnection()
	} else {
		log.Printf("failed to connect to libvirt: %s", err.Error())
		os.Exit(1)
	}

	fc, err := fuse.Mount("/srv/iso/", fuse.AllowOther(), fuse.FSName("httpfs"), fuse.Subtype("http"))
	if err != nil {
		log.Printf("Failed to mount fuse : %s\n", err.Error())
		os.Exit(1)
	}

	filesystem := &httpFS{virconn: virconn}
	if err = fs.Serve(fc, filesystem); err != nil {
		log.Printf("Failed to serve fuse : %s\n", err.Error())
		os.Exit(1)
	}

}

type httpFS struct {
	virconn libvirt.VirConnection
}

type httpDir struct {
	virconn libvirt.VirConnection
	files   []httpFile
	name    string
}

type httpFile struct {
	name string
	url  string
	size uint64
}

var _ fs.FS = (*httpFS)(nil)
var _ fs.Node = (*httpDir)(nil)
var _ = fs.NodeRequestLookuper(&httpDir{})
var _ = fs.HandleReadDirAller(&httpDir{})
var _ fs.Node = (*httpFile)(nil)
var _ fs.Handle = (*FileHandle)(nil)
var _ fs.HandleReleaser = (*FileHandle)(nil)
var _ = fs.NodeOpener(&httpFile{})

type FileHandle struct {
	buf []byte
	r   ReadSeekCloser
}

func (fh *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	fh.buf = nil
	if fh.r != nil {
		return fh.r.Close()
	}
	return nil
}

func (f *httpFile) Open(ctx context.Context, req *fuse.OpenRequest, res *fuse.OpenResponse) (fs.Handle, error) {
	hr, err := httpReadSeekCloserNew(f.url)
	if err != nil {
		return nil, fuse.EIO
	}
	fh := &FileHandle{r: hr}
	fh.buf = make([]byte, 4096)
	return fh, nil
}

func (f *httpFile) Size() uint64 {
	if f.size != 0 {
		return f.size
	}

	req, err := http.NewRequest("HEAD", f.url, nil)
	if err != nil {
		return 0
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return 0
	}

	if res.ContentLength < 1 {
		return 0
	}

	f.size = uint64(res.ContentLength)
	return f.size
}

var _ = fs.HandleReader(&FileHandle{})

func (fh *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, res *fuse.ReadResponse) error {
	_, err := fh.r.Seek(req.Offset, os.SEEK_SET)
	if err != nil {
		log.Printf("seek error: %s", err.Error())
		return fuse.EIO
	}
	n, err := fh.r.Read(fh.buf)
	if err != nil {
		log.Printf("seek error: %s", err.Error())
		return fuse.EIO
	}
	res.Data = fh.buf[:n]
	return nil
}

func (f *httpFile) Attr() fuse.Attr {
	return fuse.Attr{
		Size:   f.Size(),
		Blocks: f.Size() / 512,
		Mode:   os.FileMode(0444),
		Mtime:  time.Now(),
		Ctime:  time.Now(),
		Crtime: time.Now(),
		Uid:    uint32(os.Getuid()),
		Gid:    uint32(os.Getgid()),
	}
}

func (f *httpFS) Root() (fs.Node, error) {
	return &httpDir{virconn: f.virconn}, nil
}

func (f *httpFS) Init(ctx context.Context, req *fuse.InitRequest, res *fuse.InitResponse) error {
	res.Flags |= fuse.InitAsyncRead
	//	res.MaxReadahead = 4096
	return nil
}

func (f *httpFS) Statfs(ctx context.Context, req *fuse.StatfsRequest, res *fuse.StatfsResponse) error {
	return nil
}

func (d *httpDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	var res []fuse.Dirent
	var metadata Metadata

	if d.name == "" {
		if ok, err := d.virconn.IsAlive(); !ok || err != nil {
			return nil, fmt.Errorf("libvirt not respond")
		}

		domains, err := d.virconn.ListDefinedDomains() //ListAllDomains(libvirt.VIR_CONNECT_LIST_DOMAINS_ACTIVE | libvirt.VIR_CONNECT_LIST_DOMAINS_SHUTOFF | libvirt.VIR_CONNECT_LIST_DOMAINS_OTHER | libvirt.VIR_CONNECT_LIST_DOMAINS_INACTIVE)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup to libvirt: %s", err.Error())
		}

		for _, domain := range domains {
			res = append(res, fuse.Dirent{Type: fuse.DT_Dir, Name: domain})
		}
	} else {

		domain, err := d.virconn.LookupDomainByName(d.name)
		if err != nil {
			return nil, fuse.ENOENT
		}

		buf, err := domain.GetMetadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT, "http://simplecloud.ru/" , libvirt.VIR_DOMAIN_MEM_CURRENT)
		if err != nil {
			return nil, fuse.ENOENT
		}

		if err = xml.Unmarshal([]byte(buf), &metadata); err != nil {
			return nil, fuse.ENOENT
		}

		for _, disk := range metadata.ISO.Disks {
			res = append(res, fuse.Dirent{Type: fuse.DT_File, Name: disk.Target.Name})
		}

	}

	return res, nil
}

func (d *httpDir) Attr() fuse.Attr {
	return fuse.Attr{
		Mode:   os.FileMode(os.ModeDir | 0555),
		Uid:    uint32(os.Getuid()),
		Gid:    uint32(os.Getgid()),
		Size:   4096,
		Blocks: 4096 / 512,
	}
}

func (d *httpDir) Lookup(ctx context.Context, req *fuse.LookupRequest, res *fuse.LookupResponse) (fs.Node, error) {
	var metadata Metadata

	name := req.Name
	if d.name != "" {
		name = d.name
	}

	domain, err := d.virconn.LookupDomainByName(name)
	if err != nil {
		return nil, fuse.ENOENT
	}

	buf, err := domain.GetMetadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT, "http://simplecloud.ru/" , libvirt.VIR_DOMAIN_MEM_CURRENT)
	if err != nil {
		return nil, fuse.ENOENT
	}

	if err = xml.Unmarshal([]byte(buf), &metadata); err != nil {
		return nil, fuse.ENOENT
	}

	dir := &httpDir{name: name, virconn: d.virconn}
	for _, disk := range metadata.ISO.Disks {
		if d.name != "" {
			if disk.Target.Name == req.Name {
				return &httpFile{name: disk.Target.Name, url: disk.Source.URL}, nil
			}
		} else {
			dir.files = append(dir.files, httpFile{name: disk.Target.Name, url: disk.Source.URL})
		}
	}

	if d.name == "" {
		return dir, nil
	}

	return nil, fuse.ENOENT
}
*/
