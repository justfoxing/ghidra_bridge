import unittest
import time

import ghidra_bridge
from ghidra_bridge.server import ghidra_bridge_port


class TestGhidraBridge(unittest.TestCase):
    """ Assumes there's a ghidra bridge server running at DEFAULT_SERVER_PORT """

    def test_interactive_currentAddress(self):
        """ confirm that the current address (and ideally, the other current* vars - TODO) are updated when
            interactive mode is enabled """
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT, interactive_mode=True):
            if state.getTool() is None:
                self.skipTest(
                    "Interactive mode tests not supported against headless (no tool)")
            else:
                # record the current address as an int
                curr_addr = currentAddress.getOffset()

                # move the current address
                state.setCurrentAddress(currentAddress.add(0x10))

                # add a little sleep, so there's enough time for the update to make it back to us (interactive_mode isn't meant to be scripted...)
                time.sleep(1)

                # check the new address has changed (not sure exactly what it's changed to, because instruction alignments might change exactly where we go)
                self.assertNotEqual(curr_addr, currentAddress.getOffset())

    def test_interactive_getState_fix(self):
        """ confirm that getState is updated, and doesn't cause a reset to old values when interactive mode is enabled """
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT, interactive_mode=True):
            if state.getTool() is None:
                self.skipTest(
                    "Interactive mode tests not supported against headless (no tool)")
            else:
                # record the current address as an int
                curr_addr = currentAddress.getOffset()

                # move the current address
                state.setCurrentAddress(currentAddress.add(0x10))

                # call getState
                new_state = getState()

                # check the new address has changed (not sure exactly what it's changed to, because instruction alignments might change exactly where we go)
                self.assertNotEqual(curr_addr, currentAddress.getOffset())

                # check that the state address matches
                self.assertEqual(currentAddress.getOffset(),
                                 new_state.getCurrentAddress().getOffset())

    def test_non_interactive_currentAddress(self):
        """ confirm that the current address (and ideally, the other current* vars - TODO) are NOT updated when
            interactive mode is disabled """
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT, interactive_mode=False):
            if state.getTool() is None:
                self.skipTest(
                    "This test isn't supported against headless/no tool ghidra, because of how we try to get the most up to date addresses")
            else:
                listing_panel = ghidra_bridge.ghidra_bridge.get_listing_panel(
                    state.getTool(), ghidra)
                # get the actual current address
                actual_current_addr = listing_panel.getProgramLocation().getAddress().getOffset()

                # record the "current" address as an int
                curr_addr = currentAddress.getOffset()

                # move the current address
                state.setCurrentAddress(currentAddress.add(0x10))

                # check the address has changed
                new_actual_current_addr = listing_panel.getProgramLocation().getAddress().getOffset()
                self.assertNotEqual(actual_current_addr,
                                    new_actual_current_addr)

                # check the currentAddress hasn't changed
                self.assertEqual(curr_addr, currentAddress.getOffset())

    def test_namespace_cleanup(self):
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT):
            self.assertTrue("currentAddress" in globals())

        self.assertTrue("currentAddress" not in globals())

    def test_namespace_cleanup_with_interactive(self):
        """ check that we can still remove if the values we add have been updated by interactive mode """
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT, interactive_mode=True):
            self.assertTrue("currentAddress" in globals())

            # cause currentAddress to change
            # move the current address
            state.setCurrentAddress(currentAddress.add(0x10))

            # add a little sleep, so there's enough time for the update to make it back to us (interactive_mode isn't meant to be scripted...)
            time.sleep(1)

        # make sure it's no longer present
        self.assertTrue("currentAddress" not in globals())

    def test_isinstance_fix(self):
        """ check that we automatically fix up isinstance when using namespace, so we can isinstance bridged objects """
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT):
            self.assertTrue(isinstance(
                currentAddress, ghidra.program.model.address.Address))

    def test_str_javapackage(self):
        """ Test that we can now call str on javapackage objects """
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT):
            self.assertTrue("java package ghidra" in str(ghidra))

    def test_memory_callable_iterable(self):
        """ Test that we handle the ghidra.program.model.mem.Memory class - it's callable and iterable """
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT):
            self.assertNotEqual(None, ghidra.program.model.mem.Memory)

    def test_address_comparison(self):
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT):
            test_address = currentAddress.add(1)
            self.assertFalse(test_address < currentAddress)
            self.assertTrue(test_address > currentAddress)
            
    def test_hook_import(self):
        with ghidra_bridge.GhidraBridge(namespace=globals(), connect_to_port=ghidra_bridge_port.DEFAULT_SERVER_PORT, hook_import=True):
            import ghidra
            self.assertTrue("ghidra" in str(ghidra))
            from ghidra.framework.model import ToolListener
            import docking.widgets.indexedscrollpane.IndexScrollListener
            import java.math.BigInteger
            bi = java.math.BigInteger(str(10))
            
