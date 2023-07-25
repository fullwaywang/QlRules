/**
 * @name bzip2-74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc-BZ2_decompress
 * @id cpp/bzip2/74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc/BZ2-decompress
 * @description bzip2-74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc-decompress.c-BZ2_decompress CVE-2019-12900
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnSelectors_119, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnSelectors_119
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="18002"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnSelectors_119, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vnSelectors_119
		and target_1.getGreaterOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-4"
		and target_2.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_2.getStmt(1).(GotoStmt).getName() ="save_state_and_return"
}

predicate func_3(Variable vnSelectors_119, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnSelectors_119
}

from Function func, Variable vnSelectors_119, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vnSelectors_119, target_2, target_3, target_1)
and func_1(vnSelectors_119, target_2, target_1)
and func_2(target_2)
and func_3(vnSelectors_119, target_3)
and vnSelectors_119.getType().hasName("Int32")
and vnSelectors_119.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
