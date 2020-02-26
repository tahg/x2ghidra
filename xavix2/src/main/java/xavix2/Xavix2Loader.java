/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package xavix2;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class Xavix2Loader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "XaviX2 Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		
		boolean good = true;
		DataInputStream dis = new DataInputStream(provider.getInputStream(0));
		for (int i = 0; i < 8; i++) {
			int op = dis.readInt();
			if (op == 0) continue;
			else if ((op >>> 24) != 8 || (op & 0xFFFFFF) >= provider.length()) {
				good = false;
				break;
			}
		}
		dis.close();
		if (good) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("xavix2:LE:32:default", "default"), true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// TODO: Load the bytes from 'provider' into the 'program'.
		
        Address ram     = program.getAddressFactory().getAddressSpace("ram").getAddressInThisSpaceOnly(0x0);
        Address mirror  = program.getAddressFactory().getAddressSpace("rom").getAddressInThisSpaceOnly(0x00000000);
        Address rom     = program.getAddressFactory().getAddressSpace("rom").getAddressInThisSpaceOnly(0x40000000);
        Address io      = program.getAddressFactory().getAddressSpace("io").getAddressInThisSpaceOnly(0xFFFFE000);
        FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, TaskMonitor.DUMMY);
        try {
        	MemoryBlock ramMB = MemoryBlockUtils.createInitializedBlock(program, false, "ram", ram, 0x10000, "", "", true, true, true, log);
            MemoryBlockUtils.createInitializedBlock(program, false, "rom", rom, fileBytes, 0, provider.length(), "",
                    "", true, false, true, log);
            MemoryBlockUtils.createByteMappedBlock(program, "rommirror", mirror, rom, (int) provider.length(), "", "", true, false, true, log);
            MemoryBlockUtils.createUninitializedBlock(program, false, "io", io, 0x2000, "", "", true, true, false, log);
        	ramMB.putBytes(ram,  provider.readBytes(0, 0x10000));
        } catch (AddressOverflowException e) {
            e.printStackTrace();
        } catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
//		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
