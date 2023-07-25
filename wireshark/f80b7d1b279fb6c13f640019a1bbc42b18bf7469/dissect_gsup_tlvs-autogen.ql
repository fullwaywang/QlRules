/**
 * @name wireshark-f80b7d1b279fb6c13f640019a1bbc42b18bf7469-dissect_gsup_tlvs
 * @id cpp/wireshark/f80b7d1b279fb6c13f640019a1bbc42b18bf7469/dissect-gsup-tlvs
 * @description wireshark-f80b7d1b279fb6c13f640019a1bbc42b18bf7469-epan/dissectors/packet-gsm_gsup.c-dissect_gsup_tlvs CVE-2019-10898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vbase_offs_518, Parameter vlength_518, Parameter vpinfo_518, Parameter vgsup_ti_519, Variable voffset_521, Variable vlen_525, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, SubExpr target_5, ExprStmt target_6, AddExpr target_7) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=voffset_521
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbase_offs_518
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_525
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_518
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_518
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vgsup_ti_519
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=voffset_521
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getLeftOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vbase_offs_518, Parameter vlength_518, Variable voffset_521, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=voffset_521
		and target_2.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbase_offs_518
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vlength_518
}

predicate func_3(Parameter vpinfo_518, Parameter vgsup_ti_519, Variable voffset_521, Variable vlen_525, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("dissect_gsup_tlvs")
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_521
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_525
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpinfo_518
		and target_3.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vgsup_ti_519
}

predicate func_4(Variable voffset_521, ExprStmt target_4) {
		target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voffset_521
}

predicate func_5(Variable voffset_521, SubExpr target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=voffset_521
		and target_5.getRightOperand().(Literal).getValue()="2"
}

predicate func_6(Variable voffset_521, Variable vlen_525, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_525
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_guint8")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_521
}

predicate func_7(Variable vlen_525, AddExpr target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vlen_525
		and target_7.getAnOperand().(Literal).getValue()="2"
}

from Function func, Parameter vbase_offs_518, Parameter vlength_518, Parameter vpinfo_518, Parameter vgsup_ti_519, Variable voffset_521, Variable vlen_525, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, SubExpr target_5, ExprStmt target_6, AddExpr target_7
where
not func_1(vbase_offs_518, vlength_518, vpinfo_518, vgsup_ti_519, voffset_521, vlen_525, target_2, target_3, target_4, target_5, target_6, target_7)
and func_2(vbase_offs_518, vlength_518, voffset_521, target_2)
and func_3(vpinfo_518, vgsup_ti_519, voffset_521, vlen_525, target_3)
and func_4(voffset_521, target_4)
and func_5(voffset_521, target_5)
and func_6(voffset_521, vlen_525, target_6)
and func_7(vlen_525, target_7)
and vbase_offs_518.getType().hasName("int")
and vlength_518.getType().hasName("int")
and vpinfo_518.getType().hasName("packet_info *")
and vgsup_ti_519.getType().hasName("proto_item *")
and voffset_521.getType().hasName("int")
and vlen_525.getType().hasName("unsigned int")
and vbase_offs_518.getParentScope+() = func
and vlength_518.getParentScope+() = func
and vpinfo_518.getParentScope+() = func
and vgsup_ti_519.getParentScope+() = func
and voffset_521.getParentScope+() = func
and vlen_525.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
