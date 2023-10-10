/**
 * @name neomutt-65d64a5b60a4a3883f2cd799d92c6091d8854f23-imap_quote_string
 * @id cpp/neomutt/65d64a5b60a4a3883f2cd799d92c6091d8854f23/imap-quote-string
 * @description neomutt-65d64a5b60a4a3883f2cd799d92c6091d8854f23-imap/util.c-imap_quote_string CVE-2018-14353
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="2"
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vdlen_807, BreakStmt target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vdlen_807
		and target_1.getGreaterOperand().(Literal).getValue()="2"
		and target_1.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdlen_807, BreakStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vdlen_807
		and target_2.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vdlen_807, BreakStmt target_4, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vdlen_807
		and target_3.getAnOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BreakStmt target_4) {
		target_4.toString() = "break;"
}

predicate func_5(Parameter vdlen_807, ExprStmt target_5) {
		target_5.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vdlen_807
		and target_5.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="2"
}

predicate func_6(Parameter vdlen_807, ExprStmt target_6) {
		target_6.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vdlen_807
}

from Function func, Parameter vdlen_807, Literal target_0, VariableAccess target_2, EqualityOperation target_3, BreakStmt target_4, ExprStmt target_5, ExprStmt target_6
where
func_0(func, target_0)
and not func_1(vdlen_807, target_4, target_5, target_6)
and func_2(vdlen_807, target_4, target_2)
and func_3(vdlen_807, target_4, target_3)
and func_4(target_4)
and func_5(vdlen_807, target_5)
and func_6(vdlen_807, target_6)
and vdlen_807.getType().hasName("size_t")
and vdlen_807.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
