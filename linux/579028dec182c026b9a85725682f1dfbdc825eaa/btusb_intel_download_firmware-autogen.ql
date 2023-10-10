/**
 * @name linux-579028dec182c026b9a85725682f1dfbdc825eaa-btusb_intel_download_firmware
 * @id cpp/linux/579028dec182c026b9a85725682f1dfbdc825eaa/btusb-intel-download-firmware
 * @description linux-579028dec182c026b9a85725682f1dfbdc825eaa-btusb_intel_download_firmware CVE-2021-3564
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vhdev_2589, Variable vfw_2594, Variable vfwname_2595) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("request_firmware")
		and not target_0.getTarget().hasName("firmware_request_nowarn")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfw_2594
		and target_0.getArgument(1).(VariableAccess).getTarget()=vfwname_2595
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_2589)
}

predicate func_4(Variable vdata_2597, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof RelationalOperation
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_bit")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="5"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2597
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("set_bit")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="7"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2597
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_4))
}

predicate func_11(Variable vdata_2597) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="flags"
		and target_11.getQualifier().(VariableAccess).getTarget()=vdata_2597)
}

from Function func, Parameter vhdev_2589, Variable vfw_2594, Variable vfwname_2595, Variable verr_2596, Variable vdata_2597
where
func_0(vhdev_2589, vfw_2594, vfwname_2595)
and not func_4(vdata_2597, func)
and vhdev_2589.getType().hasName("hci_dev *")
and vfw_2594.getType().hasName("const firmware *")
and vfwname_2595.getType().hasName("char[64]")
and verr_2596.getType().hasName("int")
and vdata_2597.getType().hasName("btusb_data *")
and func_11(vdata_2597)
and vhdev_2589.getParentScope+() = func
and vfw_2594.getParentScope+() = func
and vfwname_2595.getParentScope+() = func
and verr_2596.getParentScope+() = func
and vdata_2597.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
