/**
 * @name linux-579028dec182c026b9a85725682f1dfbdc825eaa-btusb_intel_download_firmware_newgen
 * @id cpp/linux/579028dec182c026b9a85725682f1dfbdc825eaa/btusb-intel-download-firmware-newgen
 * @description linux-579028dec182c026b9a85725682f1dfbdc825eaa-btusb_intel_download_firmware_newgen CVE-2021-3564
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfw_2494, Variable vfwname_2495, Parameter vhdev_2490) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("request_firmware")
		and not target_0.getTarget().hasName("firmware_request_nowarn")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfw_2494
		and target_0.getArgument(1).(VariableAccess).getTarget()=vfwname_2495
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_2490)
}

predicate func_1(Variable verr_2496, Variable vdata_2497) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_bit")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="5"
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2497
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("set_bit")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="7"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_2497
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verr_2496
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_4(Variable vdata_2497) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="flags"
		and target_4.getQualifier().(VariableAccess).getTarget()=vdata_2497)
}

from Function func, Variable vfw_2494, Variable vfwname_2495, Variable verr_2496, Variable vdata_2497, Parameter vhdev_2490
where
func_0(vfw_2494, vfwname_2495, vhdev_2490)
and not func_1(verr_2496, vdata_2497)
and vfw_2494.getType().hasName("const firmware *")
and vfwname_2495.getType().hasName("char[64]")
and verr_2496.getType().hasName("int")
and vdata_2497.getType().hasName("btusb_data *")
and func_4(vdata_2497)
and vhdev_2490.getType().hasName("hci_dev *")
and vfw_2494.getParentScope+() = func
and vfwname_2495.getParentScope+() = func
and verr_2496.getParentScope+() = func
and vdata_2497.getParentScope+() = func
and vhdev_2490.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
