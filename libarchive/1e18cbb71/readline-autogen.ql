/**
 * @name libarchive-1e18cbb71-readline
 * @id cpp/libarchive/1e18cbb71/readline
 * @description libarchive-1e18cbb71-libarchive/archive_read_support_format_mtree.c-readline CVE-2015-8925
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vt_1921, Variable vp_1923, VariableAccess target_0) {
		target_0.getTarget()=vp_1923
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("memchr")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_1921
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="10"
}

predicate func_1(Variable vp_1923, BlockStmt target_40, VariableAccess target_1) {
		target_1.getTarget()=vp_1923
		and target_1.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_40
}

predicate func_2(Variable vp_1923, BreakStmt target_20, VariableAccess target_2) {
		target_2.getTarget()=vp_1923
		and target_2.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_20
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="0"
		and not target_3.getValue()="1"
		and target_3.getParent().(ArrayExpr).getParent().(NEExpr).getAnOperand() instanceof ArrayExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, CharLiteral target_4) {
		target_4.getValue()="92"
		and not target_4.getValue()="0"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, Literal target_5) {
		target_5.getValue()="1"
		and not target_5.getValue()="0"
		and target_5.getParent().(ArrayExpr).getParent().(EQExpr).getAnOperand() instanceof ArrayExpr
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="1"
		and not target_6.getValue()="2"
		and target_6.getParent().(PointerAddExpr).getParent().(PointerDiffExpr).getLeftOperand() instanceof PointerArithmeticOperation
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vp_1923, VariableAccess target_7) {
		target_7.getTarget()=vp_1923
}

predicate func_8(Variable vtotal_size_1919) {
	exists(AssignSubExpr target_8 |
		target_8.getLValue().(VariableAccess).getTarget()=vtotal_size_1919
		and target_8.getRValue().(Literal).getValue()="2")
}

predicate func_9(Variable vtotal_size_1919, ReturnStmt target_42) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(ArrayExpr).getArrayBase() instanceof ValueFieldAccess
		and target_9.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtotal_size_1919
		and target_9.getRValue() instanceof CharLiteral
		and target_42.getExpr().(VariableAccess).getLocation().isBefore(target_9.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_10(Variable vu_1924, ContinueStmt target_31, ArrayExpr target_10) {
		target_10.getArrayBase().(VariableAccess).getTarget()=vu_1924
		and target_10.getArrayOffset() instanceof Literal
		and target_10.getParent().(NEExpr).getAnOperand() instanceof CharLiteral
		and target_10.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_31
}

predicate func_11(Variable vu_1924, BlockStmt target_44, ArrayExpr target_11) {
		target_11.getArrayBase().(VariableAccess).getTarget()=vu_1924
		and target_11.getArrayOffset() instanceof Literal
		and target_11.getParent().(EQExpr).getAnOperand().(CharLiteral).getValue()="92"
		and target_11.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_44
}

predicate func_12(Variable vu_1924, EqualityOperation target_45, ExprStmt target_12) {
		target_12.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vu_1924
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
}

predicate func_13(Variable vu_1924, BlockStmt target_46, EqualityOperation target_13) {
		target_13.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vu_1924
		and target_13.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_13.getAnOperand().(CharLiteral).getValue()="10"
		and target_13.getParent().(IfStmt).getThen()=target_46
}

predicate func_14(Parameter vmtree_1915, ValueFieldAccess target_14) {
		target_14.getTarget().getName()="s"
		and target_14.getQualifier().(PointerFieldAccess).getTarget().getName()="line"
		and target_14.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtree_1915
}

predicate func_15(Variable vu_1924, BreakStmt target_47, ArrayExpr target_15) {
		target_15.getArrayBase().(VariableAccess).getTarget()=vu_1924
		and target_15.getArrayOffset().(Literal).getValue()="1"
		and target_15.getParent().(EQExpr).getAnOperand().(CharLiteral).getValue()="0"
		and target_15.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_47
}

predicate func_16(Parameter vmtree_1915, ValueFieldAccess target_16) {
		target_16.getTarget().getName()="s"
		and target_16.getQualifier().(PointerFieldAccess).getTarget().getName()="line"
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtree_1915
}

predicate func_18(EqualityOperation target_13, Function func, BreakStmt target_18) {
		target_18.toString() = "break;"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Variable vt_1921, Variable vs_1922, VariableAccess target_19) {
		target_19.getTarget()=vt_1921
		and target_19.getParent().(AssignExpr).getRValue() = target_19
		and target_19.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_1922
}

predicate func_20(EqualityOperation target_48, Function func, BreakStmt target_20) {
		target_20.toString() = "break;"
		and target_20.getParent().(IfStmt).getCondition()=target_48
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Variable vtotal_size_1919, VariableAccess target_21) {
		target_21.getTarget()=vtotal_size_1919
}

predicate func_22(Variable vtotal_size_1919, VariableAccess target_22) {
		target_22.getTarget()=vtotal_size_1919
}

predicate func_24(Function func, LabelStmt target_24) {
		target_24.toString() = "label ...:"
		and target_24.getEnclosingFunction() = func
}

predicate func_25(Function func, DeclStmt target_25) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_25
}

predicate func_26(Variable vt_1921, Variable vs_1922, AssignExpr target_26) {
		target_26.getLValue().(VariableAccess).getTarget()=vs_1922
		and target_26.getRValue().(VariableAccess).getTarget()=vt_1921
}

predicate func_27(Variable vp_1923, PointerArithmeticOperation target_27) {
		target_27.getAnOperand() instanceof Literal
		and target_27.getAnOperand().(VariableAccess).getTarget()=vp_1923
}

predicate func_28(Variable vs_1922, VariableAccess target_28) {
		target_28.getTarget()=vs_1922
}

predicate func_29(Parameter vstart_1915, ExprStmt target_49, AssignExpr target_29) {
		target_29.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstart_1915
		and target_29.getRValue() instanceof ValueFieldAccess
		and target_49.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_29.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_30(Variable vtotal_size_1919, EqualityOperation target_50, ReturnStmt target_42, ReturnStmt target_30) {
		target_30.getExpr().(VariableAccess).getTarget()=vtotal_size_1919
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_50
		and target_42.getExpr().(VariableAccess).getLocation().isBefore(target_30.getExpr().(VariableAccess).getLocation())
}

predicate func_31(EqualityOperation target_52, Function func, ContinueStmt target_31) {
		target_31.toString() = "continue;"
		and target_31.getParent().(IfStmt).getCondition()=target_52
		and target_31.getEnclosingFunction() = func
}

predicate func_32(EqualityOperation target_45, Function func, ContinueStmt target_32) {
		target_32.toString() = "continue;"
		and target_32.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_45
		and target_32.getEnclosingFunction() = func
}

predicate func_33(Variable vtotal_size_1919, Variable vu_1924, EqualityOperation target_13, ExprStmt target_33) {
		target_33.getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_33.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vu_1924
		and target_33.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vu_1924
		and target_33.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_33.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vtotal_size_1919
		and target_33.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vu_1924
		and target_33.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(SubExpr).getRightOperand().(PointerArithmeticOperation).getRightOperand() instanceof ValueFieldAccess
		and target_33.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

/*predicate func_34(Variable vtotal_size_1919, Variable vu_1924, SubExpr target_34) {
		target_34.getLeftOperand().(VariableAccess).getTarget()=vtotal_size_1919
		and target_34.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vu_1924
		and target_34.getRightOperand().(PointerArithmeticOperation).getRightOperand() instanceof ValueFieldAccess
}

*/
predicate func_36(Variable vtotal_size_1919, EqualityOperation target_13, ExprStmt target_36) {
		target_36.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vtotal_size_1919
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_37(Variable vu_1924, EqualityOperation target_13, ExprStmt target_37) {
		target_37.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vu_1924
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_38(Function func, IfStmt target_38) {
		target_38.getCondition().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_38.getCondition().(EqualityOperation).getAnOperand() instanceof CharLiteral
		and target_38.getThen().(BreakStmt).toString() = "break;"
		and target_38.getEnclosingFunction() = func
}

predicate func_39(Function func, LabelStmt target_39) {
		target_39.toString() = "label ...:"
		and target_39.getEnclosingFunction() = func
}

predicate func_40(Variable vs_1922, BlockStmt target_40) {
		target_40.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand() instanceof PointerArithmeticOperation
		and target_40.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vs_1922
}

predicate func_42(Variable vtotal_size_1919, ReturnStmt target_42) {
		target_42.getExpr().(VariableAccess).getTarget()=vtotal_size_1919
}

predicate func_44(BlockStmt target_44) {
		target_44.getStmt(0) instanceof ExprStmt
		and target_44.getStmt(1) instanceof ContinueStmt
}

predicate func_45(EqualityOperation target_45) {
		target_45.getAnOperand() instanceof ArrayExpr
		and target_45.getAnOperand().(CharLiteral).getValue()="92"
}

predicate func_46(BlockStmt target_46) {
		target_46.getStmt(0) instanceof ExprStmt
		and target_46.getStmt(1) instanceof ExprStmt
		and target_46.getStmt(2) instanceof ExprStmt
		and target_46.getStmt(3) instanceof BreakStmt
}

predicate func_47(BreakStmt target_47) {
		target_47.toString() = "break;"
}

predicate func_48(Variable vp_1923, EqualityOperation target_48) {
		target_48.getAnOperand().(VariableAccess).getTarget()=vp_1923
		and target_48.getAnOperand().(Literal).getValue()="0"
}

predicate func_49(Parameter vmtree_1915, Parameter vstart_1915, ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstart_1915
		and target_49.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="s"
		and target_49.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="line"
		and target_49.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtree_1915
}

predicate func_50(Variable vu_1924, EqualityOperation target_50) {
		target_50.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vu_1924
		and target_50.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_50.getAnOperand().(CharLiteral).getValue()="35"
}

predicate func_52(EqualityOperation target_52) {
		target_52.getAnOperand() instanceof ArrayExpr
		and target_52.getAnOperand() instanceof CharLiteral
}

from Function func, Parameter vmtree_1915, Parameter vstart_1915, Variable vtotal_size_1919, Variable vt_1921, Variable vs_1922, Variable vp_1923, Variable vu_1924, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, Literal target_3, CharLiteral target_4, Literal target_5, Literal target_6, VariableAccess target_7, ArrayExpr target_10, ArrayExpr target_11, ExprStmt target_12, EqualityOperation target_13, ValueFieldAccess target_14, ArrayExpr target_15, ValueFieldAccess target_16, BreakStmt target_18, VariableAccess target_19, BreakStmt target_20, VariableAccess target_21, VariableAccess target_22, LabelStmt target_24, DeclStmt target_25, AssignExpr target_26, PointerArithmeticOperation target_27, VariableAccess target_28, AssignExpr target_29, ReturnStmt target_30, ContinueStmt target_31, ContinueStmt target_32, ExprStmt target_33, ExprStmt target_36, ExprStmt target_37, IfStmt target_38, LabelStmt target_39, BlockStmt target_40, ReturnStmt target_42, BlockStmt target_44, EqualityOperation target_45, BlockStmt target_46, BreakStmt target_47, EqualityOperation target_48, ExprStmt target_49, EqualityOperation target_50, EqualityOperation target_52
where
func_0(vt_1921, vp_1923, target_0)
and func_1(vp_1923, target_40, target_1)
and func_2(vp_1923, target_20, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_7(vp_1923, target_7)
and not func_8(vtotal_size_1919)
and not func_9(vtotal_size_1919, target_42)
and func_10(vu_1924, target_31, target_10)
and func_11(vu_1924, target_44, target_11)
and func_12(vu_1924, target_45, target_12)
and func_13(vu_1924, target_46, target_13)
and func_14(vmtree_1915, target_14)
and func_15(vu_1924, target_47, target_15)
and func_16(vmtree_1915, target_16)
and func_18(target_13, func, target_18)
and func_19(vt_1921, vs_1922, target_19)
and func_20(target_48, func, target_20)
and func_21(vtotal_size_1919, target_21)
and func_22(vtotal_size_1919, target_22)
and func_24(func, target_24)
and func_25(func, target_25)
and func_26(vt_1921, vs_1922, target_26)
and func_27(vp_1923, target_27)
and func_28(vs_1922, target_28)
and func_29(vstart_1915, target_49, target_29)
and func_30(vtotal_size_1919, target_50, target_42, target_30)
and func_31(target_52, func, target_31)
and func_32(target_45, func, target_32)
and func_33(vtotal_size_1919, vu_1924, target_13, target_33)
and func_36(vtotal_size_1919, target_13, target_36)
and func_37(vu_1924, target_13, target_37)
and func_38(func, target_38)
and func_39(func, target_39)
and func_40(vs_1922, target_40)
and func_42(vtotal_size_1919, target_42)
and func_44(target_44)
and func_45(target_45)
and func_46(target_46)
and func_47(target_47)
and func_48(vp_1923, target_48)
and func_49(vmtree_1915, vstart_1915, target_49)
and func_50(vu_1924, target_50)
and func_52(target_52)
and vmtree_1915.getType().hasName("mtree *")
and vstart_1915.getType().hasName("char **")
and vtotal_size_1919.getType().hasName("ssize_t")
and vt_1921.getType().hasName("const void *")
and vs_1922.getType().hasName("const char *")
and vp_1923.getType().hasName("void *")
and vu_1924.getType().hasName("char *")
and vmtree_1915.getParentScope+() = func
and vstart_1915.getParentScope+() = func
and vtotal_size_1919.getParentScope+() = func
and vt_1921.getParentScope+() = func
and vs_1922.getParentScope+() = func
and vp_1923.getParentScope+() = func
and vu_1924.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
