/**
 * @name vim-5a73e0ca54c77e067c3b12ea6f35e3e8681e8cf8-readfile
 * @id cpp/vim/5a73e0ca54c77e067c3b12ea6f35e3e8681e8cf8/readfile
 * @description vim-5a73e0ca54c77e067c3b12ea6f35e3e8681e8cf8-src/fileio.c-readfile CVE-2017-17087
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vswap_mode_264, LogicalAndExpr target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vswap_mode_264
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(OctalLiteral).getValue()="36"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(OctalLiteral).getValue()="32"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("stat")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="st_gid"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="st_gid"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("fchown")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mf_fd"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="st_gid"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(VariableAccess).getTarget()=vswap_mode_264
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(OctalLiteral).getValue()="384"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vswap_mode_264, ExprStmt target_6) {
	exists(AssignAndExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vswap_mode_264
		and target_1.getRValue().(OctalLiteral).getValue()="384"
		and target_1.getLValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

*/
predicate func_2(Variable vswap_mode_264, LogicalAndExpr target_5) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("mch_setperm")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char_u *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vswap_mode_264
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_4(Variable vswap_mode_264, Variable vcurbuf, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="mf_fname"
		and target_4.getQualifier().(ValueFieldAccess).getTarget().getName()="ml_mfp"
		and target_4.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_4.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mch_setperm")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vswap_mode_264
}

predicate func_5(Variable vswap_mode_264, Variable vcurbuf, LogicalAndExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vswap_mode_264
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ml_mfp"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mf_fname"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ml_mfp"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vswap_mode_264, Variable vcurbuf, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("mch_setperm")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mf_fname"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ml_mfp"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vswap_mode_264
}

from Function func, Variable vswap_mode_264, Variable vcurbuf, PointerFieldAccess target_4, LogicalAndExpr target_5, ExprStmt target_6
where
not func_0(vswap_mode_264, target_5, target_6)
and not func_2(vswap_mode_264, target_5)
and func_4(vswap_mode_264, vcurbuf, target_4)
and func_5(vswap_mode_264, vcurbuf, target_5)
and func_6(vswap_mode_264, vcurbuf, target_6)
and vswap_mode_264.getType().hasName("int")
and vcurbuf.getType().hasName("buf_T *")
and vswap_mode_264.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
