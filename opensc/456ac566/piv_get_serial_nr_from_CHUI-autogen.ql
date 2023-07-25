/**
 * @name opensc-456ac566-piv_get_serial_nr_from_CHUI
 * @id cpp/opensc/456ac566/piv-get-serial-nr-from-CHUI
 * @description opensc-456ac566-src/libopensc/card-piv.c-piv_get_serial_nr_from_CHUI CVE-2021-42782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrbuf_2057, BlockStmt target_2, ExprStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrbuf_2057
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="83"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbody_2058, Variable vbodylen_2061, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbody_2058
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbodylen_2061
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vbody_2058, Variable vbodylen_2061, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_asn1_find_tag")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbody_2058
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbodylen_2061
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(HexLiteral).getValue()="48"
}

predicate func_3(Variable vrbuf_2057, Variable vbody_2058, Variable vbodylen_2061, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbody_2058
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_asn1_find_tag")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrbuf_2057
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(HexLiteral).getValue()="83"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbodylen_2061
}

from Function func, Variable vrbuf_2057, Variable vbody_2058, Variable vbodylen_2061, LogicalAndExpr target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vrbuf_2057, target_2, target_3)
and func_1(vbody_2058, vbodylen_2061, target_2, target_1)
and func_2(vbody_2058, vbodylen_2061, target_2)
and func_3(vrbuf_2057, vbody_2058, vbodylen_2061, target_3)
and vrbuf_2057.getType().hasName("u8 *")
and vbody_2058.getType().hasName("const u8 *")
and vbodylen_2061.getType().hasName("size_t")
and vrbuf_2057.getParentScope+() = func
and vbody_2058.getParentScope+() = func
and vbodylen_2061.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
