/**
 * @name opensc-456ac566-piv_general_mutual_authenticate
 * @id cpp/opensc/456ac566/piv-general-mutual-authenticate
 * @description opensc-456ac566-src/libopensc/card-piv.c-piv_general_mutual_authenticate CVE-2021-42782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrbuf_1547, BlockStmt target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrbuf_1547
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="124"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation()))
}

predicate func_1(Variable vrbuf_1547, BlockStmt target_7, ExprStmt target_8) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof NotExpr
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrbuf_1547
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="124"
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbody_1559, BlockStmt target_4, NotExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vbody_1559
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vbody_1559, BlockStmt target_7, NotExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vbody_1559
		and target_3.getParent().(IfStmt).getThen()=target_7
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Invalid Witness Data response of NULL\n"
}

predicate func_5(Variable vrbuf_1547, Variable vbody_1559, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbody_1559
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_asn1_find_tag")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrbuf_1547
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(HexLiteral).getValue()="124"
}

predicate func_6(Variable vrbuf_1547, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("piv_general_io")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(HexLiteral).getValue()="135"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vrbuf_1547
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SizeofExprOperator).getValue()="4096"
}

predicate func_7(BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log")
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Could not find outer tag 0x7C in response"
}

predicate func_8(Variable vrbuf_1547, Variable vbody_1559, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbody_1559
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_asn1_find_tag")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrbuf_1547
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(HexLiteral).getValue()="124"
}

from Function func, Variable vrbuf_1547, Variable vbody_1559, NotExpr target_2, NotExpr target_3, BlockStmt target_4, ExprStmt target_5, ExprStmt target_6, BlockStmt target_7, ExprStmt target_8
where
not func_0(vrbuf_1547, target_4, target_5, target_6)
and not func_1(vrbuf_1547, target_7, target_8)
and func_2(vbody_1559, target_4, target_2)
and func_3(vbody_1559, target_7, target_3)
and func_4(target_4)
and func_5(vrbuf_1547, vbody_1559, target_5)
and func_6(vrbuf_1547, target_6)
and func_7(target_7)
and func_8(vrbuf_1547, vbody_1559, target_8)
and vrbuf_1547.getType().hasName("u8[4096]")
and vbody_1559.getType().hasName("const u8 *")
and vrbuf_1547.getParentScope+() = func
and vbody_1559.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
