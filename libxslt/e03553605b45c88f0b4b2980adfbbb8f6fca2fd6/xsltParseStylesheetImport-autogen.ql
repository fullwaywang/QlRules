/**
 * @name libxslt-e03553605b45c88f0b4b2980adfbbb8f6fca2fd6-xsltParseStylesheetImport
 * @id cpp/libxslt/e03553605b45c88f0b4b2980adfbbb8f6fca2fd6/xsltParseStylesheetImport
 * @description libxslt-e03553605b45c88f0b4b2980adfbbb8f6fca2fd6-libxslt/imports.c-xsltParseStylesheetImport CVE-2019-11068
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsecres_130, BlockStmt target_4, ExprStmt target_5, EqualityOperation target_2) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vsecres_130
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

predicate func_2(Variable vsecres_130, BlockStmt target_4, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vsecres_130
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vURI_91, EqualityOperation target_2, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("xsltTransformError")
		and target_3.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="xsl:import: read rights for %s denied\n"
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vURI_91
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0) instanceof ExprStmt
		and target_4.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_4.getStmt(1).(GotoStmt).getName() ="error"
}

predicate func_5(Variable vURI_91, Variable vsecres_130, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsecres_130
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xsltCheckRead")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vURI_91
}

from Function func, Variable vURI_91, Variable vsecres_130, EqualityOperation target_2, ExprStmt target_3, BlockStmt target_4, ExprStmt target_5
where
not func_0(vsecres_130, target_4, target_5, target_2)
and not func_1(target_2, func)
and func_2(vsecres_130, target_4, target_2)
and func_3(vURI_91, target_2, target_3)
and func_4(target_4)
and func_5(vURI_91, vsecres_130, target_5)
and vURI_91.getType().hasName("xmlChar *")
and vsecres_130.getType().hasName("int")
and vURI_91.getParentScope+() = func
and vsecres_130.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
