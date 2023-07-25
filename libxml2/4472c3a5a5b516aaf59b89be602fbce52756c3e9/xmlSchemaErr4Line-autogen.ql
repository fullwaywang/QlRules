/**
 * @name libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlSchemaErr4Line
 * @id cpp/libxml2/4472c3a5a5b516aaf59b89be602fbce52756c3e9/xmlSchemaErr4Line
 * @description libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlschemas.c-xmlSchemaErr4Line CVE-2016-4448
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2125"
		and not target_0.getValue()="2128"
		and target_0.getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError")
		and target_0.getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericErrorContext")
		and target_0.getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="Unimplemented block at %s:%d\n"
		and target_0.getParent().(ExprCall).getParent().(ExprStmt).getExpr().(ExprCall).getArgument(2).(StringLiteral).getValue()="xmlschemas.c"
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
