/**
 * @name libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-xmlParseComment
 * @id cpp/libxml2/e50ba8164eee06461c73cd8abb9b46aa0be81869/xmlParseComment
 * @description libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-parser.c-xmlParseComment CVE-2013-2877
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_4876, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4876
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_4876, Variable vstate_4880, EqualityOperation target_3, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="instate"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4876
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_4880
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(Parameter vctxt_4876, Variable vstate_4880, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="instate"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4876
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_4880
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const xmlChar *")
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_3.getAnOperand().(CharLiteral).getValue()="62"
}

predicate func_4(Parameter vctxt_4876, ExprStmt target_4) {
		target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="comment"
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4876
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_4.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4876
		and target_4.getExpr().(VariableCall).getArgument(1).(StringLiteral).getValue()=""
}

from Function func, Parameter vctxt_4876, Variable vstate_4880, ExprStmt target_1, ExprStmt target_2, EqualityOperation target_3, ExprStmt target_4
where
not func_0(vctxt_4876, target_3, target_4, target_1)
and func_1(vctxt_4876, vstate_4880, target_3, target_1)
and func_2(vctxt_4876, vstate_4880, func, target_2)
and func_3(target_3)
and func_4(vctxt_4876, target_4)
and vctxt_4876.getType().hasName("xmlParserCtxtPtr")
and vstate_4880.getType().hasName("xmlParserInputState")
and vctxt_4876.getFunction() = func
and vstate_4880.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
