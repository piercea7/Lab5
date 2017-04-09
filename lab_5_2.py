from idaapi import *

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print "Process started, pid=%d tid=%d name=%s" % (pid, tid, name)
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        print "Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code)
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)

    def dbg_bpt(self, tid, ea):
        if ea == 0x401370:
            userpass = GetString(0x40217E, -1,0) #get user entered password and print it has issue after first print foe an unknown reason not sure how to fix. May be storing at diff address
            print "Entered Password is: %s" % (userpass)
        elif ea == 0x40123F: 
            ecx = GetRegValue("ecx")#get the value of ecx and checks if it is equal to zero was working in another test file
            if ecx != 0:
                #print "Setting Register exc to zero \n" # RIDERSOFTHESTORM was not entered so allow access 
                regval = idaapi.regval_t()
                regval.ival = 0
                idaapi.set_reg_val("ecx", regval)
            else:
                #print "Setting Register exc to non-zero \n" #RIDERSOFTHESTORM of the storm was entered so deny access
                regval = idaapi.regval_t()
                regval.ival = 15
                idaapi.set_reg_val("ecx", regval)
        #print "Break point at 0x%x pid=%d" % (ea, tid)
        return 0

    def dbg_trace(self, tid, ea):
        print tid, ea
        return 0

    def dbg_step_into(self):
        print "Step into"
        return self.dbg_step_over()

    def dbg_step_over(self):
        eip = GetRegValue("EIP")
        print "0x%x %s" % (eip, GetDisasm(eip))

        self.steps += 1
        if self.steps >= 5:
            request_exit_process()
        else:
            request_step_over()
        return 0

# Remove an existing debug hook
try:
    if debughook:
        print "Removing previous hook ..."
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# Stop at the entry point
ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

# Step one instruction
request_step_over()

# Start debugging
run_requests()

AddBpt(0x401370)#add breakpoint to get user entered string
AddBpt(0x40123F)#add breakpoint to check if user entered RIDERSOFTHESTORM or not if they did change cl to allow success if they did deny entry
