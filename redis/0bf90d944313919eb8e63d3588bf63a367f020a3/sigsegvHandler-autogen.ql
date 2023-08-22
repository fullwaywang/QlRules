/**
 * @name redis-0bf90d944313919eb8e63d3588bf63a367f020a3-sigsegvHandler
 * @id cpp/redis/0bf90d944313919eb8e63d3588bf63a367f020a3/sigsegvHandler
 * @description redis-0bf90d944313919eb8e63d3588bf63a367f020a3-src/debug.c-sigsegvHandler CVE-2022-3647
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vuc_1970, FunctionCall target_0) {
		target_0.getTarget().hasName("getMcontextEip")
		and not target_0.getTarget().hasName("getAndSetMcontextEip")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vuc_1970
}

predicate func_1(Variable vuc_1970, FunctionCall target_1) {
		target_1.getTarget().hasName("getMcontextEip")
		and not target_1.getTarget().hasName("getAndSetMcontextEip")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vuc_1970
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("logStackTrace")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

predicate func_3(Parameter vinfo_1954, Variable vuc_1970, Variable veip_1971, ValueFieldAccess target_9, ExprStmt target_10, ExprStmt target_11, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veip_1971
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="si_addr"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="_sigfault"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="_sifields"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_1954
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("invalidFunctionWasCalledType *")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("getAndSetMcontextEip")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vuc_1970
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("void *")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_3)
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Function func) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("invalidFunctionWasCalledType *")
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_6(Variable veip_1971, EqualityOperation target_12, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("logStackTrace")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veip_1971
		and target_6.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_6)
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vinfo_1954, Variable vuc_1970, Variable veip_1971, FunctionCall target_0, FunctionCall target_1, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veip_1971
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="si_addr"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="_sigfault"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="_sifields"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_1954
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("getAndSetMcontextEip")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vuc_1970
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=veip_1971
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_8)
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_9(Parameter vinfo_1954, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="_kill"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="_sifields"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_1954
}

predicate func_10(Variable vuc_1970, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("logRegisters")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vuc_1970
}

predicate func_11(Variable veip_1971, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("_serverLog")
		and target_11.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_11.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Crashed running the instruction at: %p"
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=veip_1971
}

predicate func_12(Variable veip_1971, EqualityOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=veip_1971
		and target_12.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vinfo_1954, Variable vuc_1970, Variable veip_1971, FunctionCall target_0, FunctionCall target_1, ValueFieldAccess target_9, ExprStmt target_10, ExprStmt target_11, EqualityOperation target_12
where
func_0(vuc_1970, target_0)
and func_1(vuc_1970, target_1)
and not func_3(vinfo_1954, vuc_1970, veip_1971, target_9, target_10, target_11, func)
and not func_6(veip_1971, target_12, func)
and not func_8(vinfo_1954, vuc_1970, veip_1971, target_0, target_1, func)
and func_9(vinfo_1954, target_9)
and func_10(vuc_1970, target_10)
and func_11(veip_1971, target_11)
and func_12(veip_1971, target_12)
and vinfo_1954.getType().hasName("siginfo_t *")
and vuc_1970.getType().hasName("ucontext_t *")
and veip_1971.getType().hasName("void *")
and vinfo_1954.getFunction() = func
and vuc_1970.(LocalVariable).getFunction() = func
and veip_1971.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
