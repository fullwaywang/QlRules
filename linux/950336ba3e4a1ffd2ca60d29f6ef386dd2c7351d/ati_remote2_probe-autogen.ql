/**
 * @name linux-950336ba3e4a1ffd2ca60d29f6ef386dd2c7351d-ati_remote2_probe
 * @id cpp/linux/950336ba3e4a1ffd2ca60d29f6ef386dd2c7351d/ati_remote2_probe
 * @description linux-950336ba3e4a1ffd2ca60d29f6ef386dd2c7351d-ati_remote2_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinterface_804, Variable valt_807, Variable vr_809, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_807
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="endpoint"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_807
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_err")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinterface_804
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s(): interface 0 must have an endpoint\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("const char[18]")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_809
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_4(Parameter vinterface_804, Variable vudev_806, Variable var2_808, Variable vr_809, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumInterfaces"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="actconfig"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vudev_806
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="intf"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var2_808
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_err")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinterface_804
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s(): need 2 interfaces, found %d\n"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("const char[18]")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="bNumInterfaces"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="actconfig"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vudev_806
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_809
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_4.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_4))
}

predicate func_8(Parameter vinterface_804, Variable valt_807, Variable vr_809, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_807
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="endpoint"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_807
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_err")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinterface_804
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s(): interface 1 must have an endpoint\n"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("const char[18]")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_809
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_8.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_8))
}

predicate func_12(Function func) {
	exists(LabelStmt target_12 |
		target_12.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(40)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(40).getFollowingStmt()=target_12))
}

predicate func_13(Parameter vinterface_804) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="cur_altsetting"
		and target_13.getQualifier().(VariableAccess).getTarget()=vinterface_804)
}

predicate func_14(Parameter vinterface_804, Variable var2_808) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="intf"
		and target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var2_808
		and target_14.getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_14.getRValue().(VariableAccess).getTarget()=vinterface_804)
}

predicate func_15(Variable vudev_806) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("usb_ifnum_to_if")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vudev_806
		and target_15.getArgument(1).(Literal).getValue()="1")
}

predicate func_16(Variable valt_807) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="desc"
		and target_16.getQualifier().(VariableAccess).getTarget()=valt_807)
}

predicate func_17(Variable valt_807, Variable var2_808) {
	exists(AssignExpr target_17 |
		target_17.getLValue().(VariableAccess).getTarget()=valt_807
		and target_17.getRValue().(PointerFieldAccess).getTarget().getName()="cur_altsetting"
		and target_17.getRValue().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="intf"
		and target_17.getRValue().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var2_808
		and target_17.getRValue().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_18(Variable var2_808) {
	exists(PointerFieldAccess target_18 |
		target_18.getTarget().getName()="intf"
		and target_18.getQualifier().(VariableAccess).getTarget()=var2_808)
}

from Function func, Parameter vinterface_804, Variable vudev_806, Variable valt_807, Variable var2_808, Variable vr_809
where
not func_0(vinterface_804, valt_807, vr_809, func)
and not func_4(vinterface_804, vudev_806, var2_808, vr_809, func)
and not func_8(vinterface_804, valt_807, vr_809, func)
and not func_12(func)
and vinterface_804.getType().hasName("usb_interface *")
and func_13(vinterface_804)
and func_14(vinterface_804, var2_808)
and vudev_806.getType().hasName("usb_device *")
and func_15(vudev_806)
and valt_807.getType().hasName("usb_host_interface *")
and func_16(valt_807)
and func_17(valt_807, var2_808)
and var2_808.getType().hasName("ati_remote2 *")
and func_18(var2_808)
and vr_809.getType().hasName("int")
and vinterface_804.getParentScope+() = func
and vudev_806.getParentScope+() = func
and valt_807.getParentScope+() = func
and var2_808.getParentScope+() = func
and vr_809.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
