/**
 * @name expat-9f93e8036e842329863bf20395b8fb8f73834d9e-addBinding
 * @id cpp/expat/9f93e8036e842329863bf20395b8fb8f73834d9e/addBinding
 * @description expat-9f93e8036e842329863bf20395b8fb8f73834d9e-expat/lib/xmlparse.c-addBinding CVE-2022-22822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_3670, RelationalOperation target_2, MulExpr target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3670
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="2147483623"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlen_3670, PointerFieldAccess target_4, ExprStmt target_5, MulExpr target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3670
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="2147483623"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlen_3670, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vlen_3670
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="uriAlloc"
}

predicate func_3(Variable vlen_3670, MulExpr target_3) {
		target_3.getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getLeftOperand().(SizeofTypeOperator).getValue()="1"
		and target_3.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_3670
		and target_3.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="24"
}

predicate func_4(PointerFieldAccess target_4) {
		target_4.getTarget().getName()="m_freeBindingList"
}

predicate func_5(Variable vlen_3670, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="uriAlloc"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_3670
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="24"
}

predicate func_6(Variable vlen_3670, MulExpr target_6) {
		target_6.getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getLeftOperand().(SizeofTypeOperator).getValue()="1"
		and target_6.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_3670
		and target_6.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="24"
}

from Function func, Variable vlen_3670, RelationalOperation target_2, MulExpr target_3, PointerFieldAccess target_4, ExprStmt target_5, MulExpr target_6
where
not func_0(vlen_3670, target_2, target_3)
and not func_1(vlen_3670, target_4, target_5, target_6)
and func_2(vlen_3670, target_2)
and func_3(vlen_3670, target_3)
and func_4(target_4)
and func_5(vlen_3670, target_5)
and func_6(vlen_3670, target_6)
and vlen_3670.getType().hasName("int")
and vlen_3670.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
