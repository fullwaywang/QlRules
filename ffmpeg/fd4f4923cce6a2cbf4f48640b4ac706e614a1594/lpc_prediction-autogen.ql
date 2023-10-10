/**
 * @name ffmpeg-fd4f4923cce6a2cbf4f48640b4ac706e614a1594-lpc_prediction
 * @id cpp/ffmpeg/fd4f4923cce6a2cbf4f48640b4ac706e614a1594/lpc-prediction
 * @description ffmpeg-fd4f4923cce6a2cbf4f48640b4ac706e614a1594-libavcodec/alac.c-lpc_prediction CVE-2013-0856
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnb_samples_199, Variable vi_202, ExprStmt target_2, RelationalOperation target_3, RelationalOperation target_4, ExprStmt target_5, RelationalOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_202
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnb_samples_199
		and target_0.getParent().(ForStmt).getStmt()=target_2
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlpc_order_200, Variable vi_202, ExprStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vi_202
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vlpc_order_200
		and target_1.getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(Variable vi_202, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int32_t *")
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_202
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sign_extend")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int32_t *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_202
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int32_t *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_202
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vnb_samples_199, Variable vi_202, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vi_202
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vnb_samples_199
}

predicate func_4(Parameter vnb_samples_199, Variable vi_202, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vi_202
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vnb_samples_199
}

predicate func_5(Variable vi_202, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_202
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vnb_samples_199, Parameter vlpc_order_200, Variable vi_202, RelationalOperation target_1, ExprStmt target_2, RelationalOperation target_3, RelationalOperation target_4, ExprStmt target_5
where
not func_0(vnb_samples_199, vi_202, target_2, target_3, target_4, target_5, target_1)
and func_1(vlpc_order_200, vi_202, target_2, target_1)
and func_2(vi_202, target_2)
and func_3(vnb_samples_199, vi_202, target_3)
and func_4(vnb_samples_199, vi_202, target_4)
and func_5(vi_202, target_5)
and vnb_samples_199.getType().hasName("int")
and vlpc_order_200.getType().hasName("int")
and vi_202.getType().hasName("int")
and vnb_samples_199.getFunction() = func
and vlpc_order_200.getFunction() = func
and vi_202.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
