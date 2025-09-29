import React, { useState } from "react";

export const EvidenceUpload: React.FC<{ onUpload: (file: string) => void }> = ({ onUpload }) => {
  const [dragging, setDragging] = useState(false);

  return (
    <div
      className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer ${
        dragging ? "border-blue-500 bg-blue-50" : "border-gray-300"
      }`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files[0];
        if (file) onUpload(file.name);
      }}
    >
      <p className="text-gray-600">Drag & drop evidence here, or click to upload</p>
      <input
        type="file"
        className="hidden"
        onChange={(e) => {
          if (e.target.files?.[0]) onUpload(e.target.files[0].name);
        }}
      />
    </div>
  );
};
