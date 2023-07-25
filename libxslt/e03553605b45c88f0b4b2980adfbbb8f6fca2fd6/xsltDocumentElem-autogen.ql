/**
 * @name libxslt-e03553605b45c88f0b4b2980adfbbb8f6fca2fd6-xsltDocumentElem
 * @id cpp/libxslt/e03553605b45c88f0b4b2980adfbbb8f6fca2fd6/xsltDocumentElem
 * @description libxslt-e03553605b45c88f0b4b2980adfbbb8f6fca2fd6-libxslt/transform.c-xsltDocumentElem CVE-2019-11068
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_3379, BlockStmt target_4, ExprStmt target_5, EqualityOperation target_2) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vret_3379
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

predicate func_2(Variable vret_3379, BlockStmt target_4, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vret_3379
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vctxt_3370, Parameter vinst_3371, Variable vfilename_3380, EqualityOperation target_2, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("xsltTransformError")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3370
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinst_3371
		and target_3.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="xsltDocumentElem: write rights for %s denied\n"
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vfilename_3380
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_4(Variable vfilename_3380, BlockStmt target_4) {
		target_4.getStmt(0) instanceof ExprStmt
		and target_4.getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vfilename_3380
		and target_4.getStmt(3).(ReturnStmt).toString() = "return ..."
}

predicate func_5(Parameter vctxt_3370, Variable vret_3379, Variable vfilename_3380, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_3379
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xsltCheckWrite")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sec"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3370
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vctxt_3370
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfilename_3380
}

from Function func, Parameter vctxt_3370, Parameter vinst_3371, Variable vret_3379, Variable vfilename_3380, EqualityOperation target_2, ExprStmt target_3, BlockStmt target_4, ExprStmt target_5
where
not func_0(vret_3379, target_4, target_5, target_2)
and not func_1(target_2, func)
and func_2(vret_3379, target_4, target_2)
and func_3(vctxt_3370, vinst_3371, vfilename_3380, target_2, target_3)
and func_4(vfilename_3380, target_4)
and func_5(vctxt_3370, vret_3379, vfilename_3380, target_5)
and vctxt_3370.getType().hasName("xsltTransformContextPtr")
and vinst_3371.getType().hasName("xmlNodePtr")
and vret_3379.getType().hasName("int")
and vfilename_3380.getType().hasName("xmlChar *")
and vctxt_3370.getParentScope+() = func
and vinst_3371.getParentScope+() = func
and vret_3379.getParentScope+() = func
and vfilename_3380.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
