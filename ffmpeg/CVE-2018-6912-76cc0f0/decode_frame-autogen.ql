/**
 * @name ffmpeg-76cc0f0f673353cd4746cd3b83838ae335e5d9ed-decode_frame
 * @id cpp/ffmpeg/76cc0f0f673353cd4746cd3b83838ae335e5d9ed/decode-frame
 * @description ffmpeg-76cc0f0f673353cd4746cd3b83838ae335e5d9ed-libavcodec/utvideodec.c-decode_frame CVE-2018-6912
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_597, Variable vi_598, Variable vj_598, Variable vleft_616, ReturnStmt target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="packed_stream_size"
		and target_0.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_0.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_598
		and target_0.getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_598
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vleft_616
		and target_0.getParent().(IfStmt).getThen()=target_6
		and target_7.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_597, Variable vi_598, Variable vj_598, Variable vleft_616, ReturnStmt target_9, ExprStmt target_10, ExprStmt target_11) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="control_stream_size"
		and target_1.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_1.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_598
		and target_1.getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_598
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vleft_616
		and target_1.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vleft_616, ReturnStmt target_6, VariableAccess target_2) {
		target_2.getTarget()=vleft_616
		and target_2.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_3(Variable vleft_616, ReturnStmt target_9, VariableAccess target_3) {
		target_3.getTarget()=vleft_616
		and target_3.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_3.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_4(Variable vleft_616, ReturnStmt target_6, ExprStmt target_7, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vleft_616
		and target_4.getGreaterOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_6
		and target_7.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_5(Variable vleft_616, ReturnStmt target_9, ExprStmt target_10, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vleft_616
		and target_5.getGreaterOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_6(ReturnStmt target_6) {
		target_6.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_7(Variable vc_597, Variable vi_598, Variable vj_598, Variable vleft_616, ExprStmt target_7) {
		target_7.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vleft_616
		and target_7.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="packed_stream_size"
		and target_7.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_7.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_598
		and target_7.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_598
}

predicate func_8(Variable vc_597, Variable vi_598, Variable vj_598, ExprStmt target_8) {
		target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="packed_stream_size"
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_598
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_598
}

predicate func_9(ReturnStmt target_9) {
		target_9.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_10(Variable vc_597, Variable vi_598, Variable vj_598, Variable vleft_616, ExprStmt target_10) {
		target_10.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vleft_616
		and target_10.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="control_stream_size"
		and target_10.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_10.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_598
		and target_10.getExpr().(AssignSubExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_598
}

predicate func_11(Variable vc_597, Variable vi_598, Variable vj_598, ExprStmt target_11) {
		target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="control_stream_size"
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_598
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_598
}

from Function func, Variable vc_597, Variable vi_598, Variable vj_598, Variable vleft_616, VariableAccess target_2, VariableAccess target_3, RelationalOperation target_4, RelationalOperation target_5, ReturnStmt target_6, ExprStmt target_7, ExprStmt target_8, ReturnStmt target_9, ExprStmt target_10, ExprStmt target_11
where
not func_0(vc_597, vi_598, vj_598, vleft_616, target_6, target_7, target_8)
and not func_1(vc_597, vi_598, vj_598, vleft_616, target_9, target_10, target_11)
and func_2(vleft_616, target_6, target_2)
and func_3(vleft_616, target_9, target_3)
and func_4(vleft_616, target_6, target_7, target_4)
and func_5(vleft_616, target_9, target_10, target_5)
and func_6(target_6)
and func_7(vc_597, vi_598, vj_598, vleft_616, target_7)
and func_8(vc_597, vi_598, vj_598, target_8)
and func_9(target_9)
and func_10(vc_597, vi_598, vj_598, vleft_616, target_10)
and func_11(vc_597, vi_598, vj_598, target_11)
and vc_597.getType().hasName("UtvideoContext *")
and vi_598.getType().hasName("int")
and vj_598.getType().hasName("int")
and vleft_616.getType().hasName("int")
and vc_597.getParentScope+() = func
and vi_598.getParentScope+() = func
and vj_598.getParentScope+() = func
and vleft_616.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
