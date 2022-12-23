/**
 * @name linux-11f3710417d026ea2f4fcf362d866342c5274185-ovl_rename2
 * @id cpp/linux/11f3710417d026ea2f4fcf362d866342c5274185/ovl_rename2
 * @description linux-11f3710417d026ea2f4fcf362d866342c5274185-ovl_rename2 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="0"
		and not target_2.getValue()="116"
		and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr() instanceof AssignExpr
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vnew_upperdir_711) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vnew_upperdir_711
		and target_3.getParent().(NEExpr).getAnOperand() instanceof PointerFieldAccess
		and target_3.getParent().(NEExpr).getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_4(Parameter vold_703, Variable vold_upperdir_710) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("lookup_one_len")
		and target_4.getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_4.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_name"
		and target_4.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("dentry *")
		and target_4.getArgument(1).(VariableAccess).getTarget()=vold_upperdir_710
		and target_4.getArgument(2).(ValueFieldAccess).getTarget().getName()="len"
		and target_4.getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_4.getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_4.getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_name"
		and target_4.getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vold_703)
}

predicate func_5(Variable verr_707, Variable volddentry_712) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=verr_707
		and target_5.getRValue().(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=volddentry_712)
}

predicate func_6(Variable volddentry_712) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("IS_ERR")
		and target_6.getArgument(0).(VariableAccess).getTarget()=volddentry_712)
}

predicate func_9(Variable vnewdentry_713, Variable vopaquedir_722) {
	exists(IfStmt target_9 |
		target_9.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnewdentry_713
		and target_9.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vopaquedir_722
		and target_9.getThen().(GotoStmt).toString() = "goto ..."
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vopaquedir_722)
}

predicate func_10(Variable vnewdentry_713, Variable vopaquedir_722) {
	exists(IfStmt target_10 |
		target_10.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnewdentry_713
		and target_10.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ovl_dentry_upper")
		and target_10.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("dentry *")
		and target_10.getThen().(GotoStmt).toString() = "goto ..."
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vopaquedir_722)
}

predicate func_11(Variable vnewdentry_713, Variable vnew_opaque_716) {
	exists(IfStmt target_11 |
		target_11.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("d_is_negative")
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewdentry_713
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vnew_opaque_716
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ovl_is_whiteout")
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewdentry_713
		and target_11.getThen().(GotoStmt).toString() = "goto ..."
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof FunctionCall)
}

predicate func_12(Variable volddentry_712) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("dput")
		and target_12.getArgument(0).(VariableAccess).getTarget()=volddentry_712)
}

predicate func_13(Function func) {
	exists(LabelStmt target_13 |
		target_13.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(74)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(74).getFollowingStmt()=target_13))
}

predicate func_14(Parameter vold_703) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("ovl_dentry_upper")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vold_703)
}

predicate func_15(Parameter vnew_704) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("ovl_dentry_upper")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vnew_704)
}

predicate func_16(Parameter vnew_704, Variable vnew_upperdir_711, Variable vnewdentry_713) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewdentry_713
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_one_len")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_name"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_704
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnew_upperdir_711
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="len"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_name"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_704
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnewdentry_713)
}

predicate func_17(Variable verr_707, Variable vnewdentry_713) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_707
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewdentry_713
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnewdentry_713)
}

predicate func_18(Variable vnewdentry_713) {
	exists(IfStmt target_18 |
		target_18.getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_18.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewdentry_713
		and target_18.getThen().(GotoStmt).toString() = "goto ..."
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnewdentry_713)
}

predicate func_24(Variable vnewdentry_713) {
	exists(AssignExpr target_24 |
		target_24.getLValue().(VariableAccess).getTarget()=vnewdentry_713
		and target_24.getRValue() instanceof FunctionCall)
}

predicate func_25(Variable vnewdentry_713, Variable vopaquedir_722) {
	exists(AssignExpr target_25 |
		target_25.getLValue().(VariableAccess).getTarget()=vnewdentry_713
		and target_25.getRValue().(VariableAccess).getTarget()=vopaquedir_722)
}

predicate func_26(Variable vopaquedir_722) {
	exists(AssignExpr target_26 |
		target_26.getLValue().(VariableAccess).getTarget()=vopaquedir_722
		and target_26.getRValue() instanceof Literal)
}

predicate func_27(Variable vopaquedir_722) {
	exists(ExprStmt target_27 |
		target_27.getExpr() instanceof FunctionCall
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vopaquedir_722)
}

predicate func_28(Variable volddentry_712) {
	exists(PointerFieldAccess target_28 |
		target_28.getTarget().getName()="d_parent"
		and target_28.getQualifier().(VariableAccess).getTarget()=volddentry_712)
}

predicate func_29(Variable vnewdentry_713) {
	exists(PointerFieldAccess target_29 |
		target_29.getTarget().getName()="d_parent"
		and target_29.getQualifier().(VariableAccess).getTarget()=vnewdentry_713)
}

predicate func_30(Parameter vold_703) {
	exists(PointerFieldAccess target_30 |
		target_30.getTarget().getName()="d_parent"
		and target_30.getQualifier().(VariableAccess).getTarget()=vold_703)
}

predicate func_31(Variable volddentry_712) {
	exists(AssignExpr target_31 |
		target_31.getLValue().(VariableAccess).getTarget()=volddentry_712
		and target_31.getRValue() instanceof FunctionCall)
}

predicate func_33(Parameter vnew_704, Parameter vflags_705, Variable vnew_opaque_716, Variable vcleanup_whiteout_718, Variable vis_dir_720) {
	exists(LogicalAndExpr target_33 |
		target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_dir_720
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="d_inode"
		and target_33.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_704
		and target_33.getAnOperand().(VariableAccess).getTarget()=vnew_opaque_716
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags_705
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcleanup_whiteout_718)
}

from Function func, Parameter vold_703, Parameter vnew_704, Parameter vflags_705, Variable verr_707, Variable vold_upperdir_710, Variable vnew_upperdir_711, Variable volddentry_712, Variable vnewdentry_713, Variable vnew_opaque_716, Variable vcleanup_whiteout_718, Variable vis_dir_720, Variable vopaquedir_722
where
func_2(func)
and func_3(vnew_upperdir_711)
and not func_4(vold_703, vold_upperdir_710)
and not func_5(verr_707, volddentry_712)
and not func_6(volddentry_712)
and not func_9(vnewdentry_713, vopaquedir_722)
and not func_10(vnewdentry_713, vopaquedir_722)
and not func_11(vnewdentry_713, vnew_opaque_716)
and not func_12(volddentry_712)
and not func_13(func)
and func_14(vold_703)
and func_15(vnew_704)
and func_16(vnew_704, vnew_upperdir_711, vnewdentry_713)
and func_17(verr_707, vnewdentry_713)
and func_18(vnewdentry_713)
and func_24(vnewdentry_713)
and func_25(vnewdentry_713, vopaquedir_722)
and func_26(vopaquedir_722)
and func_27(vopaquedir_722)
and func_28(volddentry_712)
and func_29(vnewdentry_713)
and vold_703.getType().hasName("dentry *")
and func_30(vold_703)
and vnew_704.getType().hasName("dentry *")
and verr_707.getType().hasName("int")
and vold_upperdir_710.getType().hasName("dentry *")
and vnew_upperdir_711.getType().hasName("dentry *")
and volddentry_712.getType().hasName("dentry *")
and func_31(volddentry_712)
and vnewdentry_713.getType().hasName("dentry *")
and vnew_opaque_716.getType().hasName("bool")
and func_33(vnew_704, vflags_705, vnew_opaque_716, vcleanup_whiteout_718, vis_dir_720)
and vcleanup_whiteout_718.getType().hasName("bool")
and vis_dir_720.getType().hasName("bool")
and vopaquedir_722.getType().hasName("dentry *")
and vold_703.getParentScope+() = func
and vnew_704.getParentScope+() = func
and vflags_705.getParentScope+() = func
and verr_707.getParentScope+() = func
and vold_upperdir_710.getParentScope+() = func
and vnew_upperdir_711.getParentScope+() = func
and volddentry_712.getParentScope+() = func
and vnewdentry_713.getParentScope+() = func
and vnew_opaque_716.getParentScope+() = func
and vcleanup_whiteout_718.getParentScope+() = func
and vis_dir_720.getParentScope+() = func
and vopaquedir_722.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
