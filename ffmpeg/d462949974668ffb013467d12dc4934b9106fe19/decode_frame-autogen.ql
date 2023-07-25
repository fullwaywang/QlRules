/**
 * @name ffmpeg-d462949974668ffb013467d12dc4934b9106fe19-decode_frame
 * @id cpp/ffmpeg/d462949974668ffb013467d12dc4934b9106fe19/decode-frame
 * @description ffmpeg-d462949974668ffb013467d12dc4934b9106fe19-libavcodec/wmalosslessdec.c-decode_frame CVE-2012-2785
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_993, Parameter vs_990, ExprStmt target_9, Function func) {
	exists(ForStmt target_0 |
		target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_993
		and target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_993
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_channels"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_0.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_993
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="samples_16"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_993
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand() instanceof ArrayExpr
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_993
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="samples_32"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_993
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand() instanceof ArrayExpr
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_993
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vi_993, Parameter vs_990) {
	exists(ArrayExpr target_2 |
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="samples_16"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vi_993
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue() instanceof ArrayExpr)
}

*/
/*predicate func_3(Variable vi_993, Parameter vs_990) {
	exists(PointerArithmeticOperation target_3 |
		target_3.getAnOperand() instanceof ArrayExpr
		and target_3.getAnOperand().(VariableAccess).getTarget()=vi_993
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="samples_16"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990)
}

*/
predicate func_4(Parameter vs_990, ArrayExpr target_4) {
		target_4.getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_4.getArrayOffset().(Literal).getValue()="0"
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="samples_16"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
}

predicate func_5(Parameter vs_990, ArrayExpr target_5) {
		target_5.getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_5.getArrayOffset().(Literal).getValue()="0"
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="samples_32"
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
}

/*predicate func_6(Parameter vs_990, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="samples_16"
		and target_6.getQualifier().(VariableAccess).getTarget()=vs_990
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_6.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_6.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_6.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_7(Parameter vs_990, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="samples_32"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_990
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_7.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_7.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_7.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
predicate func_8(Parameter vs_990, AssignExpr target_8) {
		target_8.getLValue().(PointerFieldAccess).getTarget().getName()="samples_32"
		and target_8.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_8.getRValue() instanceof ArrayExpr
}

predicate func_9(Parameter vs_990, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="packet_loss"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_990
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Variable vi_993, Parameter vs_990, ArrayExpr target_4, ArrayExpr target_5, AssignExpr target_8, ExprStmt target_9
where
not func_0(vi_993, vs_990, target_9, func)
and func_4(vs_990, target_4)
and func_5(vs_990, target_5)
and func_8(vs_990, target_8)
and func_9(vs_990, target_9)
and vi_993.getType().hasName("int")
and vs_990.getType().hasName("WmallDecodeCtx *")
and vi_993.(LocalVariable).getFunction() = func
and vs_990.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
