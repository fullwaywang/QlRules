/**
 * @name libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-xmlParseDocTypeDecl
 * @id cpp/libxml2/e50ba8164eee06461c73cd8abb9b46aa0be81869/xmlParseDocTypeDecl
 * @description libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-parser.c-xmlParseDocTypeDecl CVE-2013-2877
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_8237, ExprStmt target_1, EqualityOperation target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_8237
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_1.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_8237, ExprStmt target_1) {
		target_1.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="internalSubset"
		and target_1.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_1.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_8237
		and target_1.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_1.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_8237
		and target_1.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const xmlChar *")
		and target_1.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_1.getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("xmlChar *")
}

predicate func_2(Parameter vctxt_8237, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_8237
		and target_2.getAnOperand().(CharLiteral).getValue()="91"
}

from Function func, Parameter vctxt_8237, ExprStmt target_1, EqualityOperation target_2
where
not func_0(vctxt_8237, target_1, target_2, func)
and func_1(vctxt_8237, target_1)
and func_2(vctxt_8237, target_2)
and vctxt_8237.getType().hasName("xmlParserCtxtPtr")
and vctxt_8237.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
