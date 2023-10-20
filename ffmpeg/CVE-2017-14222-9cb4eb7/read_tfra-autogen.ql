/**
 * @name ffmpeg-9cb4eb772839c5e1de2855d126bf74ff16d13382-read_tfra
 * @id cpp/ffmpeg/9cb4eb772839c5e1de2855d126bf74ff16d13382/read-tfra
 * @description ffmpeg-9cb4eb772839c5e1de2855d126bf74ff16d13382-libavformat/mov.c-read_tfra CVE-2017-14222
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vf_6057, Variable vindex_6059, ExprStmt target_1, ExprStmt target_2, RelationalOperation target_3, ArrayExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("avio_feof")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_6057
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="item_count"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindex_6059
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_freep")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="items"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindex_6059
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vf_6057, Variable vindex_6059, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="item_count"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindex_6059
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_rb32")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_6057
}

predicate func_2(Parameter vf_6057, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_rb64")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vf_6057
}

predicate func_3(Variable vindex_6059, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="item_count"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindex_6059
}

predicate func_4(Variable vindex_6059, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="items"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindex_6059
}

from Function func, Parameter vf_6057, Variable vindex_6059, ExprStmt target_1, ExprStmt target_2, RelationalOperation target_3, ArrayExpr target_4
where
not func_0(vf_6057, vindex_6059, target_1, target_2, target_3, target_4)
and func_1(vf_6057, vindex_6059, target_1)
and func_2(vf_6057, target_2)
and func_3(vindex_6059, target_3)
and func_4(vindex_6059, target_4)
and vf_6057.getType().hasName("AVIOContext *")
and vindex_6059.getType().hasName("MOVFragmentIndex *")
and vf_6057.getParentScope+() = func
and vindex_6059.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
