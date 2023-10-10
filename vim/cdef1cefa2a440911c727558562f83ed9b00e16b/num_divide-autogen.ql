/**
 * @name vim-cdef1cefa2a440911c727558562f83ed9b00e16b-num_divide
 * @id cpp/vim/cdef1cefa2a440911c727558562f83ed9b00e16b/num-divide
 * @description vim-cdef1cefa2a440911c727558562f83ed9b00e16b-src/eval.c-num_divide CVE-2022-4293
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vn1_50, Parameter vn2_50, Variable vresult_52, EqualityOperation target_2, RelationalOperation target_3, ExprStmt target_1, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vn1_50
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getValue()="-9223372036854775808"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vn2_50
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_52
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="9223372036854775807"
		and target_0.getElse() instanceof ExprStmt
		and target_0.getParent().(IfStmt).getCondition()=target_2
		and target_3.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vn1_50, Parameter vn2_50, Variable vresult_52, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_52
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vn1_50
		and target_1.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vn2_50
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vn2_50, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vn2_50
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vn1_50, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vn1_50
		and target_3.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vresult_52, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_52
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="9223372036854775807"
}

from Function func, Parameter vn1_50, Parameter vn2_50, Variable vresult_52, ExprStmt target_1, EqualityOperation target_2, RelationalOperation target_3, ExprStmt target_4
where
not func_0(vn1_50, vn2_50, vresult_52, target_2, target_3, target_1, target_4)
and func_1(vn1_50, vn2_50, vresult_52, target_2, target_1)
and func_2(vn2_50, target_2)
and func_3(vn1_50, target_3)
and func_4(vresult_52, target_4)
and vn1_50.getType().hasName("varnumber_T")
and vn2_50.getType().hasName("varnumber_T")
and vresult_52.getType().hasName("varnumber_T")
and vn1_50.getParentScope+() = func
and vn2_50.getParentScope+() = func
and vresult_52.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
