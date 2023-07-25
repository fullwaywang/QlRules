/**
 * @name ndpi-61066fb106efa6d3d95b67e47b662de208b2b622-ndpi_parse_packet_line_info
 * @id cpp/ndpi/61066fb106efa6d3d95b67e47b662de208b2b622/ndpi-parse-packet-line-info
 * @description ndpi-61066fb106efa6d3d95b67e47b662de208b2b622-src/lib/ndpi_main.c-ndpi_parse_packet_line_info CVE-2020-15471
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdiff_4869, RelationalOperation target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdiff_4869
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdiff_4869
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="8"
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vdiff_4869
		and target_0.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="8"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_3(Variable vpacket_4845, Variable va1_4870, SubExpr target_3) {
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="payload_packet_len"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4845
		and target_3.getRightOperand().(VariableAccess).getTarget()=va1_4870
		and target_3.getParent().(LTExpr).getGreaterOperand().(SizeofExprOperator).getValue()="8"
}

predicate func_4(Variable vpacket_4845, Variable va1_4870, AddressOfExpr target_6, SubExpr target_4) {
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="payload_packet_len"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4845
		and target_4.getRightOperand().(VariableAccess).getTarget()=va1_4870
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_5(Variable vdiff_4869, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vdiff_4869
		and target_5.getLesserOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vpacket_4845, Variable va1_4870, AddressOfExpr target_6) {
		target_6.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="payload"
		and target_6.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_4845
		and target_6.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=va1_4870
}

from Function func, Variable vpacket_4845, Variable vdiff_4869, Variable va1_4870, SubExpr target_3, SubExpr target_4, RelationalOperation target_5, AddressOfExpr target_6
where
not func_0(vdiff_4869, target_5)
and func_3(vpacket_4845, va1_4870, target_3)
and func_4(vpacket_4845, va1_4870, target_6, target_4)
and func_5(vdiff_4869, target_5)
and func_6(vpacket_4845, va1_4870, target_6)
and vpacket_4845.getType().hasName("ndpi_packet_struct *")
and vdiff_4869.getType().hasName("int")
and va1_4870.getType().hasName("u_int32_t")
and vpacket_4845.getParentScope+() = func
and vdiff_4869.getParentScope+() = func
and va1_4870.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
