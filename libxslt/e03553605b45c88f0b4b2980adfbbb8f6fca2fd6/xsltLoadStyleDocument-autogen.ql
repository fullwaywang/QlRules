/**
 * @name libxslt-e03553605b45c88f0b4b2980adfbbb8f6fca2fd6-xsltLoadStyleDocument
 * @id cpp/libxslt/e03553605b45c88f0b4b2980adfbbb8f6fca2fd6/xsltLoadStyleDocument
 * @description libxslt-e03553605b45c88f0b4b2980adfbbb8f6fca2fd6-libxslt/documents.c-xsltLoadStyleDocument CVE-2019-11068
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vres_372, BlockStmt target_4, ExprStmt target_5, EqualityOperation target_2) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vres_372
		and target_0.getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_2, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof EqualityOperation
		and target_1.getThen() instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vres_372, BlockStmt target_4, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vres_372
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vURI_359, EqualityOperation target_2, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("xsltTransformError")
		and target_3.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="xsltLoadStyleDocument: read rights for %s denied\n"
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vURI_359
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0) instanceof ExprStmt
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(Parameter vURI_359, Variable vres_372, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_372
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xsltCheckRead")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vURI_359
}

from Function func, Parameter vURI_359, Variable vres_372, EqualityOperation target_2, ExprStmt target_3, BlockStmt target_4, ExprStmt target_5
where
not func_0(vres_372, target_4, target_5, target_2)
and not func_1(target_2, func)
and func_2(vres_372, target_4, target_2)
and func_3(vURI_359, target_2, target_3)
and func_4(target_4)
and func_5(vURI_359, vres_372, target_5)
and vURI_359.getType().hasName("const xmlChar *")
and vres_372.getType().hasName("int")
and vURI_359.getParentScope+() = func
and vres_372.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
