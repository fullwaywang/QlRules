/**
 * @name bzip2-74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc-BZ2_decompress
 * @id cpp/bzip2/74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc/BZ2-decompress
 * @description bzip2-74de1e2e6ffc9d51ef9824db71a8ffee5962cdbc-BZ2_decompress CVE-2019-12900
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnSelectors_119, Variable vretVal_109) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnSelectors_119
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="18002"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretVal_109
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="4"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ...")
}

predicate func_1(Variable vnSelectors_119, Variable vretVal_109) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vnSelectors_119
		and target_1.getGreaterOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretVal_109
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="4"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ...")
}

predicate func_2(Variable vnSelectors_119, Variable vv_289) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vnSelectors_119
		and target_2.getRValue().(VariableAccess).getTarget()=vv_289)
}

from Function func, Variable vnSelectors_119, Variable vretVal_109, Variable vv_289
where
not func_0(vnSelectors_119, vretVal_109)
and func_1(vnSelectors_119, vretVal_109)
and vnSelectors_119.getType().hasName("Int32")
and func_2(vnSelectors_119, vv_289)
and vretVal_109.getType().hasName("Int32")
and vv_289.getType().hasName("UInt32")
and vnSelectors_119.getParentScope+() = func
and vretVal_109.getParentScope+() = func
and vv_289.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
