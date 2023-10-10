/**
 * @name curl-fae6fea209a2d4d-hsts_create
 * @id cpp/curl/fae6fea209a2d4d/hsts-create
 * @description curl-fae6fea209a2d4d-hsts_create CVE-2022-30115
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Size_t
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_1)
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("char *")
		and target_2.getRValue() instanceof VariableCall
		and target_2.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_4))
}

predicate func_5(Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char *")
		and target_5.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char *")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_5))
}

predicate func_6(Variable vsts_116, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="host"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsts_116
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_6))
}

predicate func_8(Parameter vhostname_112, Variable vCurl_cstrdup) {
	exists(VariableCall target_8 |
		target_8.getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_8.getArgument(0).(VariableAccess).getTarget()=vhostname_112)
}

predicate func_9(Variable vsts_116) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="host"
		and target_9.getQualifier().(VariableAccess).getTarget()=vsts_116)
}

from Function func, Parameter vhostname_112, Variable vsts_116, Variable vCurl_cstrdup
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_4(func)
and not func_5(func)
and not func_6(vsts_116, func)
and func_8(vhostname_112, vCurl_cstrdup)
and func_9(vsts_116)
and vhostname_112.getType().hasName("const char *")
and vsts_116.getType().hasName("stsentry *")
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vhostname_112.getParentScope+() = func
and vsts_116.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
