/**
 * @name e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-report_tree
 * @id cpp/e2fsprogs/8dbe7b475ec5e91ed767239f0e85880f416fc384/report-tree
 * @description e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-lib/support/quotaio_tree.c-report_tree CVE-2019-5094
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable ventries_599) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=ventries_599
		and target_1.getRValue().(UnaryMinusExpr).getValue()="-1")
}

predicate func_2(EqualityOperation target_20, Function func) {
	exists(GotoStmt target_2 |
		target_2.toString() = "goto ..."
		and target_2.getName() ="errout"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("int")
		and target_3.getRValue() instanceof FunctionCall
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable ventries_599, VariableAccess target_18, ReturnStmt target_21) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventries_599
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="errout"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_21.getExpr().(VariableAccess).getLocation()))
}

/*predicate func_5(Variable ventries_599, ReturnStmt target_21) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=ventries_599
		and target_5.getRValue().(VariableAccess).getType().hasName("int")
		and target_5.getLValue().(VariableAccess).getLocation().isBefore(target_21.getExpr().(VariableAccess).getLocation()))
}

*/
predicate func_8(Parameter vblk_594, Variable ventries_599, ExprStmt target_22, ExprStmt target_24, ExprStmt target_25) {
	exists(IfStmt target_8 |
		target_8.getCondition().(VariableAccess).getTarget()=vblk_594
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof FunctionCall
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventries_599
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="errout"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ventries_599
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="errout"
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=ventries_599
		and target_8.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getCondition().(VariableAccess).getLocation())
		and target_24.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_11(Function func) {
	exists(LabelStmt target_11 |
		target_11.toString() = "label ...:"
		and target_11.getName() ="errout"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_11))
}

predicate func_12(Parameter vblk_594, Parameter vbitmap_595, ExprStmt target_24, LogicalAndExpr target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vblk_594
		and target_12.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbitmap_595
		and target_12.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vblk_594
		and target_12.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_12.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_12.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vblk_594
		and target_12.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="7"
		and target_12.getParent().(IfStmt).getThen()=target_24
}

/*predicate func_13(Parameter vdquot_594, Parameter vblk_594, Parameter vbitmap_595, Parameter vprocess_dquot_596, Parameter vdata_597, FunctionCall target_13) {
		target_13.getTarget().hasName("report_block")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vdquot_594
		and target_13.getArgument(1).(VariableAccess).getTarget()=vblk_594
		and target_13.getArgument(2).(VariableAccess).getTarget()=vbitmap_595
		and target_13.getArgument(3).(VariableAccess).getTarget()=vprocess_dquot_596
		and target_13.getArgument(4).(VariableAccess).getTarget()=vdata_597
}

*/
/*predicate func_14(Parameter vdquot_594, Parameter vblk_594, Parameter vdepth_594, Parameter vbitmap_595, Parameter vprocess_dquot_596, Parameter vdata_597, FunctionCall target_14) {
		target_14.getTarget().hasName("report_tree")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vdquot_594
		and target_14.getArgument(1).(VariableAccess).getTarget()=vblk_594
		and target_14.getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdepth_594
		and target_14.getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_14.getArgument(3).(VariableAccess).getTarget()=vbitmap_595
		and target_14.getArgument(4).(VariableAccess).getTarget()=vprocess_dquot_596
		and target_14.getArgument(5).(VariableAccess).getTarget()=vdata_597
}

*/
predicate func_15(Parameter vdquot_594, Parameter vblk_594, FunctionCall target_15) {
		target_15.getTarget().hasName("check_reference")
		and target_15.getArgument(0).(PointerFieldAccess).getTarget().getName()="dq_h"
		and target_15.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdquot_594
		and target_15.getArgument(1).(VariableAccess).getTarget()=vblk_594
}

predicate func_16(Parameter vdquot_594, Parameter vblk_594, FunctionCall target_16) {
		target_16.getTarget().hasName("check_reference")
		and target_16.getArgument(0).(PointerFieldAccess).getTarget().getName()="dq_h"
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdquot_594
		and target_16.getArgument(1).(VariableAccess).getTarget()=vblk_594
}

predicate func_17(Parameter vdquot_594, Parameter vblk_594, Parameter vbitmap_595, Parameter vprocess_dquot_596, Parameter vdata_597, Variable ventries_599, VariableAccess target_17) {
		target_17.getTarget()=ventries_599
		and target_17.getParent().(AssignAddExpr).getLValue() = target_17
		and target_17.getParent().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report_block")
		and target_17.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdquot_594
		and target_17.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vblk_594
		and target_17.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbitmap_595
		and target_17.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vprocess_dquot_596
		and target_17.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdata_597
}

predicate func_18(Parameter vblk_594, BlockStmt target_26, VariableAccess target_18) {
		target_18.getTarget()=vblk_594
		and target_18.getParent().(IfStmt).getThen()=target_26
}

predicate func_19(Parameter vdquot_594, Parameter vblk_594, Parameter vdepth_594, Parameter vbitmap_595, Parameter vprocess_dquot_596, Parameter vdata_597, Variable ventries_599, VariableAccess target_19) {
		target_19.getTarget()=ventries_599
		and target_19.getParent().(AssignAddExpr).getLValue() = target_19
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report_tree")
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdquot_594
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vblk_594
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdepth_594
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbitmap_595
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprocess_dquot_596
		and target_19.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vdata_597
}

predicate func_20(Parameter vdepth_594, EqualityOperation target_20) {
		target_20.getAnOperand().(VariableAccess).getTarget()=vdepth_594
		and target_20.getAnOperand().(SubExpr).getValue()="3"
}

predicate func_21(Variable ventries_599, ReturnStmt target_21) {
		target_21.getExpr().(VariableAccess).getTarget()=ventries_599
}

predicate func_22(Parameter vblk_594, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vblk_594
}

predicate func_24(Variable ventries_599, ExprStmt target_24) {
		target_24.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=ventries_599
		and target_24.getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_25(Variable ventries_599, ExprStmt target_25) {
		target_25.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=ventries_599
		and target_25.getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_26(Variable ventries_599, BlockStmt target_26) {
		target_26.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_26.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=ventries_599
		and target_26.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

from Function func, Parameter vdquot_594, Parameter vblk_594, Parameter vdepth_594, Parameter vbitmap_595, Parameter vprocess_dquot_596, Parameter vdata_597, Variable ventries_599, LogicalAndExpr target_12, FunctionCall target_15, FunctionCall target_16, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, EqualityOperation target_20, ReturnStmt target_21, ExprStmt target_22, ExprStmt target_24, ExprStmt target_25, BlockStmt target_26
where
not func_1(ventries_599)
and not func_2(target_20, func)
and not func_3(func)
and not func_4(ventries_599, target_18, target_21)
and not func_8(vblk_594, ventries_599, target_22, target_24, target_25)
and not func_11(func)
and func_12(vblk_594, vbitmap_595, target_24, target_12)
and func_15(vdquot_594, vblk_594, target_15)
and func_16(vdquot_594, vblk_594, target_16)
and func_17(vdquot_594, vblk_594, vbitmap_595, vprocess_dquot_596, vdata_597, ventries_599, target_17)
and func_18(vblk_594, target_26, target_18)
and func_19(vdquot_594, vblk_594, vdepth_594, vbitmap_595, vprocess_dquot_596, vdata_597, ventries_599, target_19)
and func_20(vdepth_594, target_20)
and func_21(ventries_599, target_21)
and func_22(vblk_594, target_22)
and func_24(ventries_599, target_24)
and func_25(ventries_599, target_25)
and func_26(ventries_599, target_26)
and vdquot_594.getType().hasName("dquot *")
and vblk_594.getType().hasName("unsigned int")
and vdepth_594.getType().hasName("int")
and vbitmap_595.getType().hasName("char *")
and vprocess_dquot_596.getType().hasName("..(*)(..)")
and vdata_597.getType().hasName("void *")
and ventries_599.getType().hasName("int")
and vdquot_594.getParentScope+() = func
and vblk_594.getParentScope+() = func
and vdepth_594.getParentScope+() = func
and vbitmap_595.getParentScope+() = func
and vprocess_dquot_596.getParentScope+() = func
and vdata_597.getParentScope+() = func
and ventries_599.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
