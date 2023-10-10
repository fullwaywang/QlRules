/**
 * @name libxslt-c5eb6cf3aba0af048596106ed839b4ae17ecbcb1-xsltNumberFormatTokenize
 * @id cpp/libxslt/c5eb6cf3aba0af048596106ed839b4ae17ecbcb1/xsltNumberFormatTokenize
 * @description libxslt-c5eb6cf3aba0af048596106ed839b4ae17ecbcb1-libxslt/numbers.c-xsltNumberFormatTokenize CVE-2019-13117
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtokens_328, FunctionCall target_2, ArrayExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="token"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tokens"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="nTokens"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
		and target_0.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="48"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtokens_328, FunctionCall target_2, ArrayExpr target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="width"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tokens"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="nTokens"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(FunctionCall target_2) {
		target_2.getTarget().hasName("xsltIsDigitZero")
		and target_2.getArgument(0).(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_3(Parameter vtokens_328, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="tokens"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
		and target_3.getArrayOffset().(PointerFieldAccess).getTarget().getName()="nTokens"
		and target_3.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
}

predicate func_4(Parameter vtokens_328, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="tokens"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
		and target_4.getArrayOffset().(PointerFieldAccess).getTarget().getName()="nTokens"
		and target_4.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtokens_328
}

from Function func, Parameter vtokens_328, FunctionCall target_2, ArrayExpr target_3, ArrayExpr target_4
where
not func_0(vtokens_328, target_2, target_3)
and not func_1(vtokens_328, target_2, target_4)
and func_2(target_2)
and func_3(vtokens_328, target_3)
and func_4(vtokens_328, target_4)
and vtokens_328.getType().hasName("xsltFormatPtr")
and vtokens_328.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
