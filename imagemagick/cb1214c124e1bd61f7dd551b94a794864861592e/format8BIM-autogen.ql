/**
 * @name imagemagick-cb1214c124e1bd61f7dd551b94a794864861592e-format8BIM
 * @id cpp/imagemagick/cb1214c124e1bd61f7dd551b94a794864861592e/format8BIM
 * @description imagemagick-cb1214c124e1bd61f7dd551b94a794864861592e-coders/meta.c-format8BIM CVE-2019-10131
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_2125, LogicalOrExpr target_2, RelationalOperation target_3) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vcount_2125
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcount_2125
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcount_2125, VariableAccess target_1) {
		target_1.getTarget()=vcount_2125
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
}

predicate func_2(Variable vcount_2125, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcount_2125
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_2125
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("GetBlobSize")
}

predicate func_3(Variable vcount_2125, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vcount_2125
}

from Function func, Variable vcount_2125, VariableAccess target_1, LogicalOrExpr target_2, RelationalOperation target_3
where
not func_0(vcount_2125, target_2, target_3)
and func_1(vcount_2125, target_1)
and func_2(vcount_2125, target_2)
and func_3(vcount_2125, target_3)
and vcount_2125.getType().hasName("ssize_t")
and vcount_2125.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
