/**
 * @name lcms-91c2db7f2559be504211b283bc3a2c631d6f06d9-CurvesAlloc
 * @id cpp/lcms/91c2db7f2559be504211b283bc3a2c631d6f06d9/CurvesAlloc
 * @description lcms-91c2db7f2559be504211b283bc3a2c631d6f06d9-src/cmsopt.c-CurvesAlloc CVE-2013-4160
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vContextID_1164, Variable vi_1166, Variable vj_1166, Variable vc16_1167, ExprStmt target_1, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="Curves"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc16_1167
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1166
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_1166
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_1166
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_1166
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_1166
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cmsFree")
		and target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vContextID_1164
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cmsFree")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vContextID_1164
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="Curves"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc16_1167
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cmsFree")
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vContextID_1164
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vc16_1167
		and target_0.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vContextID_1164, Variable vi_1166, Variable vc16_1167, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="Curves"
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc16_1167
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1166
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_cmsCalloc")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vContextID_1164
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="2"
}

predicate func_2(Variable vi_1166, Variable vj_1166, Variable vc16_1167, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="Curves"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc16_1167
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1166
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_1166
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cmsEvalToneCurve16")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1166
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vj_1166
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(VariableAccess).getTarget()=vj_1166
}

from Function func, Parameter vContextID_1164, Variable vi_1166, Variable vj_1166, Variable vc16_1167, ExprStmt target_1, ExprStmt target_2
where
not func_0(vContextID_1164, vi_1166, vj_1166, vc16_1167, target_1, target_2)
and func_1(vContextID_1164, vi_1166, vc16_1167, target_1)
and func_2(vi_1166, vj_1166, vc16_1167, target_2)
and vContextID_1164.getType().hasName("cmsContext")
and vi_1166.getType().hasName("int")
and vj_1166.getType().hasName("int")
and vc16_1167.getType().hasName("Curves16Data *")
and vContextID_1164.getParentScope+() = func
and vi_1166.getParentScope+() = func
and vj_1166.getParentScope+() = func
and vc16_1167.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
