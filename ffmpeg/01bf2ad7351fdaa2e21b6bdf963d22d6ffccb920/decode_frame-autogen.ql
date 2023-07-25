/**
 * @name ffmpeg-01bf2ad7351fdaa2e21b6bdf963d22d6ffccb920-decode_frame
 * @id cpp/ffmpeg/01bf2ad7351fdaa2e21b6bdf963d22d6ffccb920/decode-frame
 * @description ffmpeg-01bf2ad7351fdaa2e21b6bdf963d22d6ffccb920-libavcodec/indeo4.c-decode_frame CVE-2012-2787
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_764, Parameter vavctx_761, AddressOfExpr target_1, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("avcodec_set_dimensions")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_761
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="width"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="planes"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_764
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="height"
		and target_0.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="planes"
		and target_0.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_764
		and target_0.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vctx_764, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_764
}

predicate func_2(Variable vctx_764, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="reference"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_764
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Variable vctx_764, Parameter vavctx_761, ExprStmt target_3) {
		target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="release_buffer"
		and target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_761
		and target_3.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vavctx_761
		and target_3.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_3.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_764
}

predicate func_4(Variable vctx_764, Parameter vavctx_761, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="get_buffer"
		and target_4.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_761
		and target_4.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vavctx_761
		and target_4.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_4.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_764
		and target_4.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vctx_764, Parameter vavctx_761, AddressOfExpr target_1, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4
where
not func_0(vctx_764, vavctx_761, target_1, target_2, target_3, target_4, func)
and func_1(vctx_764, target_1)
and func_2(vctx_764, target_2)
and func_3(vctx_764, vavctx_761, target_3)
and func_4(vctx_764, vavctx_761, target_4)
and vctx_764.getType().hasName("IVI4DecContext *")
and vavctx_761.getType().hasName("AVCodecContext *")
and vctx_764.(LocalVariable).getFunction() = func
and vavctx_761.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
