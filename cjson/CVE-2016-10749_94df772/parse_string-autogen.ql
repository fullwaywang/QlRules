/**
 * @name cjson-94df772485c92866ca417d92137747b2e3b0a917-parse_string
 * @id cpp/cjson/94df772485c92866ca417d92137747b2e3b0a917/parse-string
 * @description cjson-94df772485c92866ca417d92137747b2e3b0a917-cJSON.c-parse_string CVE-2016-10749
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vend_ptr_195, EqualityOperation target_2, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_ptr_195
		and target_0.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vend_ptr_195, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vend_ptr_195
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vend_ptr_195, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vend_ptr_195
		and target_2.getAnOperand().(CharLiteral).getValue()="92"
}

from Function func, Variable vend_ptr_195, ExprStmt target_1, EqualityOperation target_2
where
not func_0(vend_ptr_195, target_2, target_1)
and func_1(vend_ptr_195, target_2, target_1)
and func_2(vend_ptr_195, target_2)
and vend_ptr_195.getType().hasName("const char *")
and vend_ptr_195.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
