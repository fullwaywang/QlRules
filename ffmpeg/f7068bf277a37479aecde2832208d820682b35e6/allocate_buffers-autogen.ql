/**
 * @name ffmpeg-f7068bf277a37479aecde2832208d820682b35e6-allocate_buffers
 * @id cpp/ffmpeg/f7068bf277a37479aecde2832208d820682b35e6/allocate-buffers
 * @description ffmpeg-f7068bf277a37479aecde2832208d820682b35e6-libavcodec/alac.c-allocate_buffers CVE-2015-6823
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vch_534, Parameter valac_532, MulExpr target_1, RelationalOperation target_2, Function func) {
	exists(ForStmt target_0 |
		target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vch_534
		and target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vch_534
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vch_534
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="predict_error_buffer"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_532
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vch_534
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="output_samples_buffer"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_532
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vch_534
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extra_bits_buffer"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_532
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vch_534
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter valac_532, MulExpr target_1) {
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="max_samples_per_frame"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_532
		and target_1.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_2(Variable vch_534, Parameter valac_532, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vch_534
		and target_2.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_2.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_532
		and target_2.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_2.getGreaterOperand().(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_2.getGreaterOperand().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="channels"
		and target_2.getGreaterOperand().(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valac_532
}

from Function func, Variable vch_534, Parameter valac_532, MulExpr target_1, RelationalOperation target_2
where
not func_0(vch_534, valac_532, target_1, target_2, func)
and func_1(valac_532, target_1)
and func_2(vch_534, valac_532, target_2)
and vch_534.getType().hasName("int")
and valac_532.getType().hasName("ALACContext *")
and vch_534.getParentScope+() = func
and valac_532.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
