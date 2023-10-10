/**
 * @name redis-48e0d4788434833b47892fe9f3d91be7687f25c9-msetGenericCommand
 * @id cpp/redis/48e0d4788434833b47892fe9f3d91be7687f25c9/msetGenericCommand
 * @description redis-48e0d4788434833b47892fe9f3d91be7687f25c9-src/t_string.c-msetGenericCommand CVE-2023-28425
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vsetkey_flags_562, AssignOrExpr target_2) {
		target_2.getLValue().(VariableAccess).getTarget()=vsetkey_flags_562
		and target_2.getRValue().(Literal).getValue()="8"
}

predicate func_3(Variable vj_561, Variable vsetkey_flags_562, Parameter vc_560, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("setKey")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_560
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="db"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_560
		and target_3.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_3.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_560
		and target_3.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_561
		and target_3.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_3.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_560
		and target_3.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vj_561
		and target_3.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsetkey_flags_562
}

/*predicate func_4(Variable vj_561, Variable vsetkey_flags_562, Parameter vc_560, VariableAccess target_4) {
		target_4.getTarget()=vsetkey_flags_562
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("setKey")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_560
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="db"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_560
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_560
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_561
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_560
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vj_561
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

*/
from Function func, Variable vj_561, Variable vsetkey_flags_562, Parameter vc_560, DeclStmt target_1, AssignOrExpr target_2, ExprStmt target_3
where
func_1(func, target_1)
and func_2(vsetkey_flags_562, target_2)
and func_3(vj_561, vsetkey_flags_562, vc_560, target_3)
and vj_561.getType().hasName("int")
and vsetkey_flags_562.getType().hasName("int")
and vc_560.getType().hasName("client *")
and vj_561.(LocalVariable).getFunction() = func
and vsetkey_flags_562.(LocalVariable).getFunction() = func
and vc_560.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
