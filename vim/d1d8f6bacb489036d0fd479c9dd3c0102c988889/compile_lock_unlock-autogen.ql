/**
 * @name vim-d1d8f6bacb489036d0fd479c9dd3c0102c988889-compile_lock_unlock
 * @id cpp/vim/d1d8f6bacb489036d0fd479c9dd3c0102c988889/compile-lock-unlock
 * @description vim-d1d8f6bacb489036d0fd479c9dd3c0102c988889-src/vim9cmds.c-compile_lock_unlock CVE-2022-2819
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_186, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_186
		and target_0.getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_10
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcmd_226, EqualityOperation target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("semsg")
		and target_1.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_1.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("char[]")
		and target_1.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcmd_226
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4)
}

predicate func_2(EqualityOperation target_4, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vret_187, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof EqualityOperation
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_187
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_3.getElse().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_3.getElse().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_3.getElse().(BlockStmt).getStmt(3) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_3))
}

predicate func_4(Variable vbuf_189, ExprStmt target_10, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vbuf_189
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_10
}

predicate func_5(EqualityOperation target_4, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vp_186, Variable vlen_188, Variable vbuf_189, Variable vcmd_226, Parameter vdeep_181, EqualityOperation target_4, IfStmt target_6) {
		target_6.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdeep_181
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_snprintf")
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_189
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_188
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s! %s"
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcmd_226
		and target_6.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vp_186
		and target_6.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_snprintf")
		and target_6.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_189
		and target_6.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_188
		and target_6.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s %d %s"
		and target_6.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcmd_226
		and target_6.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdeep_181
		and target_6.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vp_186
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_7(Variable vret_187, Variable vbuf_189, Variable visn_190, Variable vcctx_184, EqualityOperation target_4, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_187
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("generate_EXEC_copy")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcctx_184
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=visn_190
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_189
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_8(Variable vbuf_189, EqualityOperation target_4, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_189
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_9(Parameter vname_end_179, Variable vcc_185, EqualityOperation target_4, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vname_end_179
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcc_185
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_10(Variable vret_187, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_187
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_11(Variable vp_186, Variable vlen_188, Parameter vname_end_179, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_188
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vname_end_179
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_186
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="20"
}

predicate func_12(Variable vp_186, Variable vlen_188, Variable vbuf_189, Variable vcmd_226, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("vim_snprintf")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_189
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_188
		and target_12.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s! %s"
		and target_12.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcmd_226
		and target_12.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vp_186
}

from Function func, Variable vp_186, Variable vret_187, Variable vlen_188, Variable vbuf_189, Variable visn_190, Variable vcmd_226, Parameter vname_end_179, Parameter vdeep_181, Variable vcctx_184, Variable vcc_185, EqualityOperation target_4, DeclStmt target_5, IfStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12
where
not func_0(vp_186, target_10, target_11, target_12)
and not func_1(vcmd_226, target_4)
and not func_2(target_4, func)
and not func_3(vret_187, func)
and func_4(vbuf_189, target_10, target_4)
and func_5(target_4, func, target_5)
and func_6(vp_186, vlen_188, vbuf_189, vcmd_226, vdeep_181, target_4, target_6)
and func_7(vret_187, vbuf_189, visn_190, vcctx_184, target_4, target_7)
and func_8(vbuf_189, target_4, target_8)
and func_9(vname_end_179, vcc_185, target_4, target_9)
and func_10(vret_187, target_10)
and func_11(vp_186, vlen_188, vname_end_179, target_11)
and func_12(vp_186, vlen_188, vbuf_189, vcmd_226, target_12)
and vp_186.getType().hasName("char_u *")
and vret_187.getType().hasName("int")
and vlen_188.getType().hasName("size_t")
and vbuf_189.getType().hasName("char_u *")
and visn_190.getType().hasName("isntype_T")
and vcmd_226.getType().hasName("char *")
and vname_end_179.getType().hasName("char_u *")
and vdeep_181.getType().hasName("int")
and vcctx_184.getType().hasName("cctx_T *")
and vcc_185.getType().hasName("int")
and vp_186.getParentScope+() = func
and vret_187.getParentScope+() = func
and vlen_188.getParentScope+() = func
and vbuf_189.getParentScope+() = func
and visn_190.getParentScope+() = func
and vcmd_226.getParentScope+() = func
and vname_end_179.getParentScope+() = func
and vdeep_181.getParentScope+() = func
and vcctx_184.getParentScope+() = func
and vcc_185.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
