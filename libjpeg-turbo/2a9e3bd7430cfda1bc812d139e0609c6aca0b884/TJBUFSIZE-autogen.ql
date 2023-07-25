/**
 * @name libjpeg-turbo-2a9e3bd7430cfda1bc812d139e0609c6aca0b884-TJBUFSIZE
 * @id cpp/libjpeg-turbo/2a9e3bd7430cfda1bc812d139e0609c6aca0b884/TJBUFSIZE
 * @description libjpeg-turbo-2a9e3bd7430cfda1bc812d139e0609c6aca0b884-turbojpeg.c-TJBUFSIZE CVE-2019-2201
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vretval_514, Variable verrStr, ExprStmt target_3, ReturnStmt target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vretval_514
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrStr
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="200"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="TJBUFSIZE(): Image is too large"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_514
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_1.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="bailout"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vretval_514, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_514
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="6"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2048"
}

predicate func_4(Variable vretval_514, ReturnStmt target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vretval_514
}

predicate func_5(Variable verrStr, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=verrStr
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="200"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_5.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="TJBUFSIZE(): Invalid argument"
}

from Function func, Variable vretval_514, Variable verrStr, ExprStmt target_3, ReturnStmt target_4, ExprStmt target_5
where
not func_1(vretval_514, verrStr, target_3, target_4, target_5, func)
and func_3(vretval_514, target_3)
and func_4(vretval_514, target_4)
and func_5(verrStr, target_5)
and vretval_514.getType().hasName("unsigned long")
and verrStr.getType() instanceof ArrayType
and vretval_514.getParentScope+() = func
and not verrStr.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
