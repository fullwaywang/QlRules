/**
 * @name imagemagick-824f344ceb823e156ad6e85314d79c087933c2a0-TIFFGetProfiles
 * @id cpp/imagemagick/824f344ceb823e156ad6e85314d79c087933c2a0/TIFFGetProfiles
 * @description imagemagick-824f344ceb823e156ad6e85314d79c087933c2a0-coders/tiff.c-TIFFGetProfiles CVE-2020-13902
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtiff_670, LogicalAndExpr target_3, EqualityOperation target_4, LogicalAndExpr target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const TIFFField *")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFFieldWithTag")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_670
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="33723"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vimage_670, Parameter vexception_671, Variable vstatus_674, Variable vlength_677, Variable vprofile_680, LogicalAndExpr target_3, ExprStmt target_6, ExprStmt target_2, ExprStmt target_7, MulExpr target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("TIFFFieldDataType")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const TIFFField *")
		and target_1.getThen() instanceof ExprStmt
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_674
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadProfile")
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_670
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="iptc"
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprofile_680
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlength_677
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vexception_671
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_8.getRightOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vimage_670, Parameter vexception_671, Variable vstatus_674, Variable vlength_677, Variable vprofile_680, LogicalAndExpr target_3, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_674
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadProfile")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_670
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="iptc"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprofile_680
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vlength_677
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vexception_671
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vlength_677, Variable vprofile_680, Parameter vtiff_670, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_670
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="33723"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlength_677
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vprofile_680
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vprofile_680
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vtiff_670, EqualityOperation target_4) {
		target_4.getAnOperand().(FunctionCall).getTarget().hasName("TIFFIsByteSwapped")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_670
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vlength_677, Variable vprofile_680, Parameter vtiff_670, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_670
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="700"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlength_677
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vprofile_680
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vprofile_680
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Parameter vimage_670, Parameter vexception_671, Variable vstatus_674, Variable vlength_677, Variable vprofile_680, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_674
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadProfile")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_670
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="8bim"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprofile_680
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlength_677
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vexception_671
}

predicate func_7(Variable vlength_677, Variable vprofile_680, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("TIFFSwabArrayOfLong")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_680
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_677
}

predicate func_8(Variable vlength_677, MulExpr target_8) {
		target_8.getLeftOperand().(Literal).getValue()="4"
		and target_8.getRightOperand().(VariableAccess).getTarget()=vlength_677
}

from Function func, Parameter vimage_670, Parameter vexception_671, Variable vstatus_674, Variable vlength_677, Variable vprofile_680, Parameter vtiff_670, ExprStmt target_2, LogicalAndExpr target_3, EqualityOperation target_4, LogicalAndExpr target_5, ExprStmt target_6, ExprStmt target_7, MulExpr target_8
where
not func_0(vtiff_670, target_3, target_4, target_5)
and not func_1(vimage_670, vexception_671, vstatus_674, vlength_677, vprofile_680, target_3, target_6, target_2, target_7, target_8)
and func_2(vimage_670, vexception_671, vstatus_674, vlength_677, vprofile_680, target_3, target_2)
and func_3(vlength_677, vprofile_680, vtiff_670, target_3)
and func_4(vtiff_670, target_4)
and func_5(vlength_677, vprofile_680, vtiff_670, target_5)
and func_6(vimage_670, vexception_671, vstatus_674, vlength_677, vprofile_680, target_6)
and func_7(vlength_677, vprofile_680, target_7)
and func_8(vlength_677, target_8)
and vimage_670.getType().hasName("Image *")
and vexception_671.getType().hasName("ExceptionInfo *")
and vstatus_674.getType().hasName("MagickBooleanType")
and vlength_677.getType().hasName("uint32")
and vprofile_680.getType().hasName("unsigned char *")
and vtiff_670.getType().hasName("TIFF *")
and vimage_670.getParentScope+() = func
and vexception_671.getParentScope+() = func
and vstatus_674.getParentScope+() = func
and vlength_677.getParentScope+() = func
and vprofile_680.getParentScope+() = func
and vtiff_670.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
