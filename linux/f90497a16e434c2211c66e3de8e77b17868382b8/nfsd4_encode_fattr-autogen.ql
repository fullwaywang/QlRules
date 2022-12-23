/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_encode_fattr
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-encode-fattr
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_encode_fattr 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="2479"
		and not target_0.getValue()="2565"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2480"
		and not target_1.getValue()="2566"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vparent_stat_3285, Parameter vexp_2831) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("get_parent_attributes")
		and not target_2.getTarget().hasName("nfsd4_get_mounted_on_ino")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vexp_2831
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparent_stat_3285)
}

predicate func_3(Variable vino_3286, Parameter vexp_2831) {
	exists(AddressOfExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vino_3286
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nfsd4_get_mounted_on_ino")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexp_2831)
}

predicate func_5(Variable vbmval1_2836) {
	exists(DeclStmt target_5 |
		target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vbmval1_2836
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="23")
}

predicate func_6(Variable vparent_stat_3285) {
	exists(VariableAccess target_6 |
		target_6.getTarget()=vparent_stat_3285)
}

predicate func_7(Variable vparent_stat_3285, Variable vino_3286, Parameter vexp_2831, Parameter vdentry_2832, Parameter vignore_crossmnt_2833) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vino_3286
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ino"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vparent_stat_3285
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vignore_crossmnt_2833
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdentry_2832
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mnt_root"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mnt"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ex_path"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexp_2831)
}

from Function func, Variable vparent_stat_3285, Variable vino_3286, Parameter vexp_2831, Parameter vdentry_2832, Parameter vignore_crossmnt_2833, Variable vbmval1_2836
where
func_0(func)
and func_1(func)
and func_2(vparent_stat_3285, vexp_2831)
and not func_3(vino_3286, vexp_2831)
and func_5(vbmval1_2836)
and func_6(vparent_stat_3285)
and func_7(vparent_stat_3285, vino_3286, vexp_2831, vdentry_2832, vignore_crossmnt_2833)
and vparent_stat_3285.getType().hasName("kstat")
and vino_3286.getType().hasName("u64")
and vexp_2831.getType().hasName("svc_export *")
and vdentry_2832.getType().hasName("dentry *")
and vignore_crossmnt_2833.getType().hasName("int")
and vbmval1_2836.getType().hasName("u32")
and vparent_stat_3285.getParentScope+() = func
and vino_3286.getParentScope+() = func
and vexp_2831.getParentScope+() = func
and vdentry_2832.getParentScope+() = func
and vignore_crossmnt_2833.getParentScope+() = func
and vbmval1_2836.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
