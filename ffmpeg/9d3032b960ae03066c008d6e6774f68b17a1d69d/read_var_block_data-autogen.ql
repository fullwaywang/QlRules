/**
 * @name ffmpeg-9d3032b960ae03066c008d6e6774f68b17a1d69d-read_var_block_data
 * @id cpp/ffmpeg/9d3032b960ae03066c008d6e6774f68b17a1d69d/read-var-block-data
 * @description ffmpeg-9d3032b960ae03066c008d6e6774f68b17a1d69d-libavcodec/alsdec.c-read_var_block_data CVE-2012-2775
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbd_594, Variable vsconf_596, Variable vavctx_597, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3, AddExpr target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="opt_order"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_594
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="max_order"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsconf_596
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_597
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Order too large\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vsconf_596, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="adapt_order"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsconf_596
}

predicate func_2(Parameter vbd_594, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="opt_order"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_594
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("GetBitContext *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vbd_594, Variable vsconf_596, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="opt_order"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_594
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="max_order"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsconf_596
}

predicate func_4(Variable vsconf_596, AddExpr target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="max_order"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsconf_596
		and target_4.getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vavctx_597, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_597
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Block length is not evenly divisible by the number of subblocks.\n"
}

predicate func_6(Variable vavctx_597, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_597
		and target_6.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Quantization coefficient %d is out of range.\n"
		and target_6.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int32_t *")
		and target_6.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("unsigned int")
}

from Function func, Parameter vbd_594, Variable vsconf_596, Variable vavctx_597, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3, AddExpr target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vbd_594, vsconf_596, vavctx_597, target_1, target_2, target_3, target_4, target_5, target_6)
and func_1(vsconf_596, target_1)
and func_2(vbd_594, target_2)
and func_3(vbd_594, vsconf_596, target_3)
and func_4(vsconf_596, target_4)
and func_5(vavctx_597, target_5)
and func_6(vavctx_597, target_6)
and vbd_594.getType().hasName("ALSBlockData *")
and vsconf_596.getType().hasName("ALSSpecificConfig *")
and vavctx_597.getType().hasName("AVCodecContext *")
and vbd_594.getFunction() = func
and vsconf_596.(LocalVariable).getFunction() = func
and vavctx_597.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
