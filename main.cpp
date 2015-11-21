#include <windows.h>
#include <vector>
#include <stdint.h>

#include <string>
#include <map>
#include <set>
#include <stdexcept>
#include <iostream>
#include <cassert>
#include <tuple>

typedef uint64_t elfaddr_t;
typedef uint64_t elfoff_t;

struct elf_header_t
{
	uint8_t e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	elfaddr_t e_entry;
	elfoff_t e_phoff;
	elfoff_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct elf_raw_section_header_t
{
	uint32_t sh_name; /* Section name */
	uint32_t sh_type; /* Section type */
	uint64_t sh_flags; /* Section attributes */
	elfaddr_t sh_addr; /* Virtual address in memory */
	elfoff_t sh_offset; /* Offset in file */
	uint64_t sh_size; /* Size of section */
	uint32_t sh_link; /* Link to other section */
	uint32_t sh_info; /* Miscellaneous information */
	uint64_t sh_addralign; /* Address alignment boundary */
	uint64_t sh_entsize; /* Size of entries, if section has table */
};

static uint32_t const PF_X = 0x1;
static uint32_t const PF_W = 0x2;
static uint32_t const PF_R = 0x4;

struct elf_prog_header_t
{
	uint32_t p_type; /* Type of segment */
	uint32_t p_flags; /* Segment attributes */
	elfoff_t p_offset; /* Offset in file */
	elfaddr_t p_vaddr; /* Virtual address in memory */
	elfaddr_t p_paddr; /* Reserved */
	uint64_t p_filesz; /* Size of segment in file */
	uint64_t p_memsz; /* Size of segment in memory */
	uint64_t p_align; /* Alignment of segment */
};

static uint32_t const PT_NULL = 0;
static uint32_t const PT_LOAD = 1;
static uint32_t const PT_DYNAMIC = 2;
static uint32_t const PT_INTERP = 3;
static uint32_t const PT_NOTE = 4;
static uint32_t const PT_SHLIB = 5;
static uint32_t const PT_PHDR = 6;

struct elf_section_header_t
{
	char const * name;
	elf_raw_section_header_t raw_header;
};

struct elf_dynamic_entry_t
{
	int64_t d_tag;
	union {
		uint64_t d_val;
		elfaddr_t d_ptr;
	};
};

enum : int64_t
{
	DT_NULL = 0,
	DT_NEEDED = 1,
	DT_PLTRELSZ = 2,
	DT_PLTGOT = 3,
	DT_HASH = 4,
	DT_STRTAB = 5,
	DT_SYMTAB = 6,
	DT_RELA = 7,
	DT_RELASZ = 8,
	DT_RELAENT = 9,
	DT_STRSZ = 10,
	DT_SYMENT = 11,
	DT_INIT = 12,
	DT_FINI = 13,
	DT_SONAME = 14,
	DT_RPATH = 15,
	DT_SYMBOLIC = 16,
	DT_REL = 17,
	DT_RELSZ = 18,
	DT_RELENT = 19,
	DT_PLTREL = 20,
	DT_DEBUG = 21,
	DT_TEXTREL = 22,
	DT_JMPREL = 23,
	DT_BIND_NOW = 24,
	DT_GNU_HASH = 0x6ffffef5,
};

struct elf_symbol_t
{
	uint32_t st_name;
	uint8_t st_info;
	uint8_t st_other;
	uint16_t st_shndx;
	elfaddr_t st_value;
	uint64_t st_size;
};

struct elf_rel_t
{
	elfaddr_t r_offset;
	uint32_t r_type;
	uint32_t r_sym;
};

struct elf_rela_t
{
	elfaddr_t r_offset;
	uint32_t r_type;
	uint32_t r_sym;
	int64_t r_addend;
};

enum
{
	R_X86_64_NONE = 0,
	R_X86_64_64 = 1,
	R_X86_64_PC32 = 2,
	R_X86_64_GOT32 = 3,
	R_X86_64_PLT32 = 4,
	R_X86_64_COPY = 5,
	R_X86_64_GLOB_DAT = 6,
	R_X86_64_JUMP_SLOT = 7,
	R_X86_64_RELATIVE = 8,
	R_X86_64_GOTPCREL = 9,
	R_X86_64_32 = 10,
	R_X86_64_32S = 11,
	R_X86_64_16 = 12,
	R_X86_64_PC16 = 13,
	R_X86_64_8 = 14,
	R_X86_64_PC8 = 15,
	R_X86_64_DTPMOD64 = 16,
	R_X86_64_DTPOFF64 = 17,
	R_X86_64_TPOFF64 = 18,
	R_X86_64_TLSGD = 19,
	R_X86_64_TLSLD = 20,
	R_X86_64_DTPOFF32 = 21,
	R_X86_64_GOTTPOFF = 22,
	R_X86_64_TPOFF32 = 23,
	R_X86_64_PC64 = 24,
	R_X86_64_GOTOFF64 = 25,
	R_X86_64_GOTPC32 = 26,
	R_X86_64_SIZE32 = 32,
	R_X86_64_SIZE64 = 33,
	R_X86_64_GOTPC32_TLSDESC = 34,
	R_X86_64_TLSDESC_CALL = 35,
	R_X86_64_TLSDESC = 36,
	R_X86_64_IRELATIVE = 37
};

struct elf_gnu_hash_header_t
{
	uint32_t l_nbuckets;
	uint32_t l_symndx;
	uint32_t l_maskwords;
	uint32_t l_shift2;
};

static uint32_t dl_new_hash(char const * s)
{
	uint_fast32_t h = 5381;
	while (*s)
		h = h * 33 + *s++;
	return (uint32_t)h;
}

static void read(HANDLE hFile, uint64_t offset, void * buffer, size_t len)
{
	LONG offsetHigh = offset >> 32;
	SetFilePointer(hFile, offset, &offsetHigh, SEEK_SET);

	DWORD dwRead;
	ReadFile(hFile, buffer, len, &dwRead, 0);
}

class module_manager
{
private:
	struct map_info
	{
		size_t vaddr;
		size_t size;
		size_t paddr;
	};

	struct module
	{
		std::string name;

		HANDLE hFile;
		HANDLE hSection;
		int refcount;

		std::vector<elf_prog_header_t> prog_headers;
		std::vector<elf_section_header_t> sec_headers;
		uint64_t base;
		size_t map_progress;

		elf_header_t header;
		elf_dynamic_entry_t const * dyn;
		char const * dyn_strtab;
		elf_symbol_t const * syms;
		elf_rela_t const * rela;
		uint64_t rela_count;
		elf_rela_t const * jmprela;
		uint64_t jmprela_count;
		void * pltgot;

		elf_gnu_hash_header_t const * gnu_hash;
		uint64_t const * gnu_hash_bloom;
		uint32_t const * gnu_hash_buckets;
		uint32_t const * gnu_hash_vals;

		module()
			: hFile(0), hSection(0), refcount(0), base(0), map_progress(0),
			dyn(0), dyn_strtab(0), syms(0), rela(0), rela_count(0), jmprela(0), jmprela_count(0), pltgot(0),
			gnu_hash(0), gnu_hash_bloom(0), gnu_hash_buckets(0), gnu_hash_vals(0)
		{
		}

		~module();

		elf_dynamic_entry_t const * find_dyn(int64_t tag);
		void unmap();
	};

	typedef std::map<std::string, module>::iterator module_iterator;

public:
	explicit module_manager(char const * base_dir);
	module_iterator load(char const * fname);
	void run(char const * fname);

private:
	bool try_map(module & m, uint64_t base);
	module_iterator load_unresolved(char const * fname);
	std::pair<module const *, elf_symbol_t const *> lookup(char const * sym) const;
	void reloc(module & m, elf_rela_t const * rela, uint64_t rela_count);

	std::map<std::string, module> m_modules;
	DWORD m_allocation_granularity;
	std::string m_base_dir;
	uint64_t m_last_base;
};

class win32_error
	: public std::runtime_error
{
public:
	win32_error()
		: std::runtime_error(""), dwError(::GetLastError())
	{
	}

	explicit win32_error(DWORD dwError)
		: std::runtime_error(""), dwError(dwError)
	{
	}

	DWORD error_code() const
	{
		return dwError;
	}

private:
	DWORD dwError;
};

module_manager::module::~module()
{
	this->unmap();
	if (hSection)
		CloseHandle(hSection);
	if (hFile)
		CloseHandle(hFile);
}

void module_manager::module::unmap()
{
	while (map_progress)
	{
		elf_prog_header_t const & ph = prog_headers[--map_progress];
		if (ph.p_type != PT_LOAD)
			continue;

		if (ph.p_flags & PF_W)
		{
			VirtualFree((LPVOID)ph.p_paddr, 0, MEM_RELEASE);
		}
		else
		{
			UnmapViewOfFile((LPCBYTE)ph.p_paddr);
		}
	}
}

elf_dynamic_entry_t const * module_manager::module::find_dyn(int64_t tag)
{
	elf_dynamic_entry_t const * res = dyn;
	for (; res->d_tag != DT_NULL; ++res)
	{
		if (res->d_tag == tag)
			return res;
	}
	return 0;
}

void module_manager::reloc(module & m, elf_rela_t const * rela, uint64_t rela_count)
{
	for (size_t i = 0; i < rela_count; ++i)
	{
		elf_rela_t const & r = rela[i];
		elf_symbol_t const & sym = m.syms[r.r_sym];
		char const * symname = m.dyn_strtab + sym.st_name;

		module const * rmod = 0;
		elf_symbol_t const * rsym = 0;
		if (r.r_sym)
		{
			std::tie(rmod, rsym) =this->lookup(symname);
			if (!rsym)
				continue;
		}

		void * ptr = (void *)(r.r_offset + m.base);
		switch (r.r_type)
		{
		case R_X86_64_16:
			*(uint16_t *)ptr = rsym->st_value + rmod->base + r.r_addend;
			break;
		case R_X86_64_64:
			*(uint64_t *)ptr = rsym->st_value + rmod->base + r.r_addend;
			break;
		case R_X86_64_COPY:
			break;
		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
			*(uint64_t *)ptr = rsym->st_value + rmod->base;
			break;
		case R_X86_64_RELATIVE:
			*(uint64_t *)ptr = m.base + r.r_addend;
			break;
		case R_X86_64_DTPMOD64:
		case R_X86_64_TPOFF64:
			break; // XXX
		case R_X86_64_IRELATIVE:
			*(uint64_t *)ptr = *(uint64_t *)(m.base + r.r_addend);
			break;
		default:
			assert(0);
		}
	}
}

struct scope_guard_base
{
public:
	scope_guard_base()
		: m_dismissed(false)
	{
	}

	void dismiss() const
	{
		m_dismissed = true;
	}

protected:
	mutable bool m_dismissed;
};

template <typename F>
struct scope_guard_impl
	: scope_guard_base
{
	explicit scope_guard_impl(F const & f)
		: m_f(f)
	{
	}

	~scope_guard_impl()
	{
		if (!m_dismissed)
			m_f();
	}

	F m_f;
};

typedef scope_guard_base const & scope_guard;

template <typename F>
scope_guard_impl<F> make_scope_guard(F const & f)
{
	return scope_guard_impl<F>(f);
}

bool module_manager::try_map(module & m, uint64_t base)
{
	scope_guard unmapper = make_scope_guard([&m]() { m.unmap(); });

	for (; m.map_progress < m.prog_headers.size(); ++m.map_progress)
	{
		elf_prog_header_t & ph = m.prog_headers[m.map_progress];
		if (ph.p_type != PT_LOAD)
			continue;

		uint64_t file_offset = ph.p_offset;
		uint64_t aligned_offset = file_offset & ~(uint64_t)(m_allocation_granularity - 1);

		uint64_t vaddr = ph.p_vaddr - (file_offset - aligned_offset);
		ph.p_paddr = base + vaddr;

		if (!(ph.p_flags & PF_W))
		{
			DWORD dwDesiredAccess = 0;
			switch (ph.p_flags & (PF_R|PF_W|PF_X))
			{
			case 0: dwDesiredAccess = FILE_MAP_READ; break;
			case PF_R: dwDesiredAccess = FILE_MAP_READ; break;
			case PF_X: dwDesiredAccess = FILE_MAP_READ | FILE_MAP_EXECUTE; break;
			case PF_R|PF_X: dwDesiredAccess = FILE_MAP_READ | FILE_MAP_EXECUTE; break;
			}

			uint64_t aligned_size = ph.p_filesz + (file_offset - aligned_offset);
			if (!MapViewOfFileEx(m.hSection, dwDesiredAccess, aligned_offset >> 32, aligned_offset, aligned_size, (LPVOID)ph.p_paddr))
			{
				DWORD dwError = GetLastError();
				if (dwError != ERROR_INVALID_ADDRESS)
					throw win32_error(dwError);
				return false;
			}
		}
		else
		{
			DWORD flProtect = 0;
			switch (ph.p_flags & (PF_R|PF_W|PF_X))
			{
			case PF_W: flProtect = PAGE_READWRITE; break;
			case PF_R|PF_W: flProtect = PAGE_READWRITE; break;
			case PF_W|PF_X: flProtect = PAGE_EXECUTE_READWRITE; break;
			case PF_R|PF_W|PF_X: flProtect = PAGE_EXECUTE_READWRITE; break;
			}

			uint64_t aligned_size = ph.p_memsz + (file_offset - aligned_offset);
			if (!VirtualAlloc((LPVOID)ph.p_paddr, aligned_size, MEM_COMMIT | MEM_RESERVE, flProtect))
			{
				DWORD dwError = GetLastError();
				if (dwError != ERROR_INVALID_ADDRESS)
					throw win32_error(dwError);
				return false;
			}

			read(m.hFile, ph.p_offset, (void *)(base + ph.p_vaddr), ph.p_filesz);
		}
	}

	unmapper.dismiss();
	return true;
}

module_manager::module_manager(char const * base_dir)
	: m_base_dir(base_dir), m_last_base(0x4000000)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	m_allocation_granularity = si.dwAllocationGranularity;
}

std::pair<module_manager::module const *, elf_symbol_t const *> module_manager::lookup(char const * sym) const
{
	uint32_t hash = dl_new_hash(sym);

	for (std::pair<std::string const, module> const & mod: m_modules)
	{
		module const & m = mod.second;

		/*uint32_t hash2 = hash >> m.gnu_hash->l_shift2;
		uint32_t bloom_word = (hash >> 6) & (m.gnu_hash->l_maskwords - 1);
		uint64_t mask = (uint64_t(1)<<(hash & 0x3f)) | (uint64_t(1)<<(hash2 & 0x3f));
		if ((m.gnu_hash_bloom[bloom_word] & mask) != mask)
			continue;*/

		uint32_t bucket = hash % m.gnu_hash->l_nbuckets;
		uint32_t idx = m.gnu_hash_buckets[bucket];
		if (idx == 0)
			continue;

		uint32_t const * hashval = &m.gnu_hash_vals[idx - m.gnu_hash->l_symndx];
		elf_symbol_t const * ss = &m.syms[idx];
		for (;;)
		{
			uint32_t h2 = *hashval++;
			if (((hash ^ h2) | 1) == 1)
			{
				if (strcmp(sym, m.dyn_strtab + ss->st_name) == 0)
					return std::make_pair(&m, ss);
			}

			if (h2 & 1)
				break;

			++ss;
		}
	}

	return std::pair<module_manager::module const *, elf_symbol_t const *>(0, 0);
}

void module_manager::run(char const * fname)
{
	module_manager::module_iterator mod = this->load(fname);
	module const & m = mod->second;

	// XXX
	void (*entry)() = (void (*)())(m.header.e_entry + m.base);
	entry();
}

module_manager::module_iterator module_manager::load(char const * fname)
{
	module_manager::module_iterator res = this->load_unresolved(fname);

	for (std::pair<std::string const, module> & mod: m_modules)
	{
		module & m = mod.second;
		this->reloc(m, m.rela, m.rela_count);
		this->reloc(m, m.jmprela, m.jmprela_count);
	}

	return res;
}

module_manager::module_iterator module_manager::load_unresolved(char const * fname)
{
	std::string path = fname;
	std::size_t slash_pos = path.find_last_of("/\\");
	if (slash_pos != std::string::npos)
		path = path.substr(slash_pos + 1);
	path = m_base_dir + "\\" + path;

	module_manager::module_iterator res = m_modules.find(path);
	if (res == m_modules.end())
		res = m_modules.insert(std::make_pair(path, module())).first;

	module & m = res->second;
	if (m.refcount++ != 0)
		return res;

	m.name = path;

	HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		throw win32_error();
	m.hFile = hFile;

	m.hSection = CreateFileMapping(m.hFile, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
	if (!m.hSection)
		throw win32_error();

	read(m.hFile, 0, &m.header, sizeof m.header);

	m.prog_headers.resize(m.header.e_phnum);
	uint64_t off = m.header.e_phoff;
	for (elf_prog_header_t & ph: m.prog_headers)
	{
		read(m.hFile, off, &ph, sizeof ph);
		off += m.header.e_phentsize;
	}

	uint64_t base = m_last_base;
	while (!this->try_map(m, base))
		base += m_allocation_granularity * 32;
	m.base = base;

	m_last_base = base + m_allocation_granularity * 32;

	m.sec_headers.resize(m.header.e_shnum);
	off = m.header.e_shoff;
	for (size_t i = 0; i < m.sec_headers.size(); ++i)
	{
		read(m.hFile, off, &m.sec_headers[i].raw_header, sizeof(elf_raw_section_header_t));
		off += m.header.e_shentsize;
	}

	std::vector<char> string_table(m.sec_headers[m.header.e_shstrndx].raw_header.sh_size);
	read(m.hFile, m.sec_headers[m.header.e_shstrndx].raw_header.sh_offset, string_table.data(), string_table.size());

	for (size_t i = 0; i < m.sec_headers.size(); ++i)
		m.sec_headers[i].name = string_table.data() + m.sec_headers[i].raw_header.sh_name;

	m.dyn = 0;
	for (size_t i = 0; i < m.prog_headers.size(); ++i)
	{
		elf_prog_header_t const & ph = m.prog_headers[i];
		if (ph.p_type == PT_DYNAMIC)
		{
			m.dyn = (elf_dynamic_entry_t const *)(ph.p_vaddr + base);
			break;
		}
	}

	m.dyn_strtab = (char const *)(m.find_dyn(DT_STRTAB)->d_ptr + base);

	for (elf_dynamic_entry_t const * p = m.dyn; p->d_tag != DT_NULL; ++p)
	{
		switch (p->d_tag)
		{
		case DT_NEEDED:
			this->load_unresolved((char const *)(m.dyn_strtab + p->d_val));
			break;
		case DT_SYMTAB:
			m.syms = (elf_symbol_t const *)(p->d_ptr + base);
			break;
		case DT_RELA:
			m.rela = (elf_rela_t const *)(p->d_ptr + base);
			break;
		case DT_RELASZ:
			m.rela_count = p->d_val / sizeof(elf_rela_t);
			break;
		case DT_JMPREL:
			m.jmprela = (elf_rela_t const *)(p->d_ptr + base);
			break;
		case DT_PLTRELSZ:
			m.jmprela_count = p->d_val / sizeof(elf_rela_t);
			break;
		case DT_PLTGOT:
			m.pltgot = (void *)(p->d_val + base);
			break;
		case DT_GNU_HASH:
			m.gnu_hash = (elf_gnu_hash_header_t const *)(p->d_ptr + base);
			m.gnu_hash_bloom = (uint64_t const *)(p->d_ptr + base + sizeof(elf_gnu_hash_header_t));
			m.gnu_hash_buckets = (uint32_t const *)(p->d_ptr + base + sizeof(elf_gnu_hash_header_t) + 8*m.gnu_hash->l_maskwords);
			m.gnu_hash_vals = (uint32_t const *)(p->d_ptr + base + sizeof(elf_gnu_hash_header_t) + 8*m.gnu_hash->l_maskwords + 4*m.gnu_hash->l_nbuckets);
			break;
		}
	}

	return res;
}


// FIXME: unicode support
int main(int argc, char * argv[])
{
	module_manager mm(argv[1]);
	try
	{
		mm.run(argv[2]);
	}
	catch (win32_error const & e)
	{
		std::cerr << "Failed with error " << e.error_code() << std::endl;
		return 1;
	}
}
