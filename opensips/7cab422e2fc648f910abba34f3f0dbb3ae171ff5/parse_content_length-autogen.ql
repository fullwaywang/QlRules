/**
 * @name opensips-7cab422e2fc648f910abba34f3f0dbb3ae171ff5-parse_content_length
 * @id cpp/opensips/7cab422e2fc648f910abba34f3f0dbb3ae171ff5/parse-content-length
 * @description opensips-7cab422e2fc648f910abba34f3f0dbb3ae171ff5-parser/parse_content.c-parse_content_length CVE-2023-28097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="%s [%d] %sERROR:core:%s: number overflow at pos %d in len number [%.*s]\n"
		and not target_0.getValue()="%s [%d] %sERROR:core:%s: integer overflow risk at pos %d in len number [%.*s]\n"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="%sERROR:core:%s: number overflow at pos %d in len number [%.*s]\n"
		and not target_1.getValue()="%sERROR:core:%s: integer overflow risk at pos %d in len number [%.*s]\n"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="0"
		and not target_2.getValue()="214748363"
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vnumber_229, BlockStmt target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vnumber_229
		and target_3.getLesserOperand().(Literal).getValue()="214748363"
		and target_3.getParent().(IfStmt).getThen()=target_6
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_4(Variable vnumber_229, BlockStmt target_6, VariableAccess target_4) {
		target_4.getTarget()=vnumber_229
		and target_4.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_5(Variable vnumber_229, BlockStmt target_6, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vnumber_229
		and target_5.getGreaterOperand() instanceof Literal
		and target_5.getParent().(IfStmt).getThen()=target_6
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_6.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-1"
		and target_6.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(EmptyStmt).toString() = ";"
		and target_6.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_7(Variable vnumber_229, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnumber_229
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnumber_229
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="10"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(CharLiteral).getValue()="48"
}

predicate func_8(Variable vnumber_229, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnumber_229
}

from Function func, Variable vnumber_229, StringLiteral target_0, StringLiteral target_1, Literal target_2, VariableAccess target_4, RelationalOperation target_5, BlockStmt target_6, ExprStmt target_7, ExprStmt target_8
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and not func_3(vnumber_229, target_6, target_7, target_8)
and func_4(vnumber_229, target_6, target_4)
and func_5(vnumber_229, target_6, target_5)
and func_6(target_6)
and func_7(vnumber_229, target_7)
and func_8(vnumber_229, target_8)
and vnumber_229.getType().hasName("int")
and vnumber_229.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
