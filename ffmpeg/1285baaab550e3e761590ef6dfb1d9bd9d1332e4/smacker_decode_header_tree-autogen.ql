/**
 * @name ffmpeg-1285baaab550e3e761590ef6dfb1d9bd9d1332e4-smacker_decode_header_tree
 * @id cpp/ffmpeg/1285baaab550e3e761590ef6dfb1d9bd9d1332e4/smacker-decode-header-tree
 * @description ffmpeg-1285baaab550e3e761590ef6dfb1d9bd9d1332e4-libavcodec/smacker.c-smacker_decode_header_tree CVE-2011-3944
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhuff_179, Variable vctx_183, Parameter vsmk_176, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="current"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vhuff_179
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="length"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vhuff_179
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="last"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_183
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="last"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsmk_176
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="bigtree damaged\n"
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(47)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(47).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vhuff_179, Variable vctx_183, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="last"
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_183
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_1.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="current"
		and target_1.getExpr().(AssignExpr).getRValue().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vhuff_179
}

predicate func_2(Variable vhuff_179, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int **")
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="values"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vhuff_179
}

predicate func_3(Parameter vsmk_176, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsmk_176
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Skipping high bytes tree\n"
}

from Function func, Variable vhuff_179, Variable vctx_183, Parameter vsmk_176, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vhuff_179, vctx_183, vsmk_176, target_1, target_2, target_3, func)
and func_1(vhuff_179, vctx_183, target_1)
and func_2(vhuff_179, target_2)
and func_3(vsmk_176, target_3)
and vhuff_179.getType().hasName("HuffContext")
and vctx_183.getType().hasName("DBCtx")
and vsmk_176.getType().hasName("SmackVContext *")
and vhuff_179.(LocalVariable).getFunction() = func
and vctx_183.(LocalVariable).getFunction() = func
and vsmk_176.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
