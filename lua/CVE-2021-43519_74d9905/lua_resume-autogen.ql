/**
 * @name lua-74d99057a5146755e737c479850f87fd0e3b6868-lua_resume
 * @id cpp/lua/74d99057a5146755e737c479850f87fd0e3b6868/lua-resume
 * @description lua-74d99057a5146755e737c479850f87fd0e3b6868-ldo.c-lua_resume CVE-2021-43519
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vL_804, Parameter vnargs_804, ExprStmt target_2, FunctionCall target_3, AddressOfExpr target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nCcalls"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_804
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="65535"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="200"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("resume_error")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_804
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="C stack overflow"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnargs_804
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vL_804, ExprStmt target_5, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nCcalls"
		and target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_804
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vL_804, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nCcalls"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_804
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("lua_State *")
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nCcalls"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("lua_State *")
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="65535"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_3(Parameter vL_804, Parameter vnargs_804, FunctionCall target_3) {
		target_3.getTarget().hasName("resume_error")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vL_804
		and target_3.getArgument(1).(StringLiteral).getValue()="cannot resume dead coroutine"
		and target_3.getArgument(2).(VariableAccess).getTarget()=vnargs_804
}

predicate func_4(Parameter vnargs_804, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vnargs_804
}

predicate func_5(Parameter vL_804, ExprStmt target_5) {
		target_5.getExpr().(VariableAccess).getTarget()=vL_804
}

from Function func, Parameter vL_804, Parameter vnargs_804, ExprStmt target_2, FunctionCall target_3, AddressOfExpr target_4, ExprStmt target_5
where
not func_0(vL_804, vnargs_804, target_2, target_3, target_4, func)
and not func_1(vL_804, target_5, func)
and func_2(vL_804, target_2)
and func_3(vL_804, vnargs_804, target_3)
and func_4(vnargs_804, target_4)
and func_5(vL_804, target_5)
and vL_804.getType().hasName("lua_State *")
and vnargs_804.getType().hasName("int")
and vL_804.getFunction() = func
and vnargs_804.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
