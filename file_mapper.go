package memfs

import (
	"syscall"
	"unsafe"
)

type TBigByteArray [0x3FFFFFFFFFFFF]byte
type PBigByteArray *TBigByteArray

type tFileMappingObject struct {
	FileHandle    syscall.Handle
	MappingObject syscall.Handle
	Addr          uintptr
	Size          uint64
}

type IFileMapper interface {
	BaseAddress() PBigByteArray
	GetSize() uint64
	Munmap()
}

var (
	modkernel32     = syscall.NewLazyDLL("kernel32.dll")
	procGetFileSize = modkernel32.NewProc("GetFileSizeEx")
)

func getFileSize(H syscall.Handle) (uint64, bool) {
	var L uint64
	r0, _, _ := syscall.Syscall(procGetFileSize.Addr(), 2, uintptr(H), uintptr(unsafe.Pointer(&L)), 0)
	return L, (r0 == 0)
}

func Mmap(fileName string) (IFileMapper, error) {
	var R tFileMappingObject
	var E error

	R.FileHandle, E = syscall.Open(fileName, syscall.O_RDONLY, 0)
	if E != nil {
		return nil, E
	}

	R.MappingObject, E = syscall.CreateFileMapping(R.FileHandle, nil,
		2, 0, 0, nil)
	if E != nil {
		syscall.Close(R.FileHandle)
		return nil, E
	}

	R.Addr, E = syscall.MapViewOfFile(R.MappingObject, 4, 0, 0, 0)
	if R.Addr == 0 {
		syscall.Close(R.MappingObject)
		syscall.Close(R.FileHandle)
		return nil, E
	}

	R.Size, _ = getFileSize(R.FileHandle)

	return IFileMapper(&R), nil
}

func (self *tFileMappingObject) Munmap() {
	syscall.UnmapViewOfFile(self.Addr)
	syscall.Close(self.MappingObject)
	syscall.Close(self.FileHandle)
}

func (self *tFileMappingObject) BaseAddress() PBigByteArray {
	return PBigByteArray(unsafe.Pointer(self.Addr))
}

func (self *tFileMappingObject) GetSize() uint64 {
	return self.Size
}
