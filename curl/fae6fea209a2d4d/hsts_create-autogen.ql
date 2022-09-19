import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("char *")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("size_t")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vhostname, Variable vCurl_cstrdup) {
	exists(AssignExpr target_2 |
		target_2.getType().hasName("char *")
		and target_2.getLValue().(VariableAccess).getType().hasName("char *")
		and target_2.getRValue().(VariableCall).getType().hasName("char *")
		and target_2.getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_2.getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vhostname)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getType().hasName("size_t")
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("size_t")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EQExpr).getType().hasName("int")
		and target_5.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getType().hasName("char")
		and target_5.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char *")
		and target_5.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getType().hasName("unsigned long")
		and target_5.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getCondition().(EQExpr).getRightOperand().(CharLiteral).getValue()="46"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getType().hasName("char")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getType().hasName("char")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char *")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vsts) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getType().hasName("const char *")
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="host"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("const char *")
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsts
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char *"))
}

predicate func_8(Parameter vhostname, Variable vCurl_cstrdup) {
	exists(VariableCall target_8 |
		target_8.getType().hasName("char *")
		and target_8.getExpr().(VariableAccess).getTarget()=vCurl_cstrdup
		and target_8.getArgument(0).(VariableAccess).getTarget()=vhostname)
}

predicate func_9(Variable vsts) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="host"
		and target_9.getType().hasName("const char *")
		and target_9.getQualifier().(VariableAccess).getTarget()=vsts)
}

from Function func, Parameter vhostname, Variable vsts, Variable vCurl_cstrdup
where
not func_0(func)
and not func_1(func)
and not func_2(vhostname, vCurl_cstrdup)
and not func_4(func)
and not func_5(func)
and not func_6(vsts)
and func_8(vhostname, vCurl_cstrdup)
and func_9(vsts)
and vhostname.getType().hasName("const char *")
and vsts.getType().hasName("stsentry *")
and vCurl_cstrdup.getType().hasName("curl_strdup_callback")
and vhostname.getParentScope+() = func
and vsts.getParentScope+() = func
and not vCurl_cstrdup.getParentScope+() = func
select func, vhostname, vsts, vCurl_cstrdup
