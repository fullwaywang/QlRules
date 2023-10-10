/**
 * @name libarchive-e37b620fe8f14535d737e89a4dcabaed4517bf1a-safe_fprintf
 * @id cpp/libarchive/e37b620fe8f14535d737e89a4dcabaed4517bf1a/safe-fprintf
 * @description libarchive-e37b620fe8f14535d737e89a4dcabaed4517bf1a-tar/util.c-safe_fprintf CVE-2016-8687
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_1, Function func, SubExpr target_0) {
		target_0.getValue()="236"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_1
		and target_0.getEnclosingFunction() = func
}

predicate func_1(BlockStmt target_1) {
		target_1.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_1.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s"
		and target_1.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, SubExpr target_0, BlockStmt target_1
where
func_0(target_1, func, target_0)
and func_1(target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
