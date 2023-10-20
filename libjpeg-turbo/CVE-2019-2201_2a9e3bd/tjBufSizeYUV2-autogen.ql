/**
 * @name libjpeg-turbo-2a9e3bd7430cfda1bc812d139e0609c6aca0b884-tjBufSizeYUV2
 * @id cpp/libjpeg-turbo/2a9e3bd7430cfda1bc812d139e0609c6aca0b884/tjBufSizeYUV2
 * @description libjpeg-turbo-2a9e3bd7430cfda1bc812d139e0609c6aca0b884-turbojpeg.c-tjBufSizeYUV2 CVE-2019-2201
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vretval_532, ExprStmt target_8, UnaryMinusExpr target_0) {
		target_0.getValue()="-1"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_532
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_2(Variable vretval_532) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vretval_532
		and target_2.getRValue().(UnaryMinusExpr).getValue()="18446744073709551615")
}

predicate func_3(Variable vretval_532, Variable verrStr, ExprStmt target_8, ReturnStmt target_9, ExprStmt target_10, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vretval_532
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrStr
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="200"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="tjBufSizeYUV2(): Image is too large"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_532
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_3.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="bailout"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_3)
		and target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(VariableAccess).getLocation())
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_7(Variable vretval_532, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vretval_532
		and target_7.getRValue() instanceof UnaryMinusExpr
}

predicate func_8(Variable vretval_532, ExprStmt target_8) {
		target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vretval_532
}

predicate func_9(Variable vretval_532, ReturnStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vretval_532
}

predicate func_10(Variable verrStr, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrStr
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="200"
		and target_10.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_10.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="tjBufSizeYUV2(): Invalid argument"
}

from Function func, Variable vretval_532, Variable verrStr, UnaryMinusExpr target_0, AssignExpr target_7, ExprStmt target_8, ReturnStmt target_9, ExprStmt target_10
where
func_0(vretval_532, target_8, target_0)
and not func_2(vretval_532)
and not func_3(vretval_532, verrStr, target_8, target_9, target_10, func)
and func_7(vretval_532, target_7)
and func_8(vretval_532, target_8)
and func_9(vretval_532, target_9)
and func_10(verrStr, target_10)
and vretval_532.getType().hasName("int")
and verrStr.getType() instanceof ArrayType
and vretval_532.getParentScope+() = func
and not verrStr.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
